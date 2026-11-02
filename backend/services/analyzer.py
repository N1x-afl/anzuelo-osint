import io
import ipaddress
import re
import socket
import email
from email import policy
from urllib.parse import urlparse, urljoin
from PIL import Image
from pyzbar.pyzbar import decode as decode_qr
import dns.resolver
import requests

from backend.services import threat_intel

# Protección anti-SSRF para analyze_url_chain: el servidor NO debe seguir URLs
# que apunten a redes privadas/internas, loopback o al endpoint de metadata de
# nube (169.254.169.254, cubierto por "link-local"). Se valida el esquema y la
# IP resuelta antes de CADA conexión, incluida cada redirección de la cadena
# — no alcanza con chequear solo la URL inicial, porque una URL pública
# perfectamente válida puede redirigir (302) hacia una interna.
ALLOWED_URL_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5


class ForensicAnalyzer:

    @staticmethod
    def analyze_email_headers(raw_headers: str) -> dict:
        msg = email.message_from_string(raw_headers, policy=policy.default)
        
        from_header = msg.get("From", "Desconocido")
        to_header = msg.get("To", "Desconocido")
        subject = msg.get("Subject", "Sin asunto")
        date_header = msg.get("Date", "")
        received_hops = msg.get_all("Received", [])

        domain = ""
        match_email = re.search(r"@([\w.-]+)", from_header)
        if match_email:
            domain = match_email.group(1).strip(">")

        spf_status = "NOT_FOUND"
        dmarc_status = "NOT_FOUND"
        mx_records = []

        if domain:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0

            try:
                txt_answers = resolver.resolve(domain, "TXT")
                for rdata in txt_answers:
                    txt_str = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if txt_str.startswith("v=spf1"):
                        spf_status = f"DETECTED: {txt_str[:50]}..."
                        break
            except Exception:
                spf_status = "FAIL_OR_NONE"

            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_answers:
                    txt_str = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if txt_str.startswith("v=DMARC1"):
                        dmarc_status = f"DETECTED: {txt_str[:50]}..."
                        break
            except Exception:
                dmarc_status = "FAIL_OR_NONE"

            try:
                mx_answers = resolver.resolve(domain, "MX")
                mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
            except Exception:
                pass

        risk_score = 0
        if "FAIL" in spf_status or spf_status == "NOT_FOUND":
            risk_score += 40
        if "FAIL" in dmarc_status or dmarc_status == "NOT_FOUND":
            risk_score += 40
        if not mx_records:
            risk_score += 20

        # Threat Intelligence: reputación del dominio del remitente en VirusTotal
        ti_domain = threat_intel.check_domain_virustotal(domain)
        if ti_domain.get("found"):
            if ti_domain.get("malicious", 0) > 0:
                risk_score += 50
            elif ti_domain.get("suspicious", 0) > 0:
                risk_score += 20

        # Threat Intelligence: edad del dominio del remitente (WHOIS)
        ti_whois = threat_intel.check_domain_whois(domain)
        if ti_whois.get("found"):
            age_days = ti_whois.get("age_days", 9999)
            if age_days < 30:
                risk_score += 40
            elif age_days < 180:
                risk_score += 20

        risk_score = min(risk_score, 100)

        return {
            "from": from_header,
            "to": to_header,
            "subject": subject,
            "date": date_header,
            "domain": domain,
            "hops_count": len(received_hops),
            "spf": spf_status,
            "dmarc": dmarc_status,
            "mx_records": mx_records,
            "risk_score": risk_score,
            "verdict": "Alto Riesgo (Spoofing probable)" if risk_score >= 60 else "Bajo Riesgo / Alineado",
            "threat_intel": {
                "virustotal_domain": ti_domain,
                "whois_domain": ti_whois
            }
        }

    @staticmethod
    def analyze_sms(text: str) -> dict:
        triggers = [
            "urgente", "bloqueo", "cuenta", "inmediato", "banco", "suspensión", 
            "multa", "afip", "correo", "paquete", "premio", "seguridad", "clave", "token"
        ]
        text_lower = text.lower()
        matched_triggers = [t for t in triggers if t in text_lower]

        urls = re.findall(r'(https?://[^\s]+)', text)
        urgency_score = min(len(matched_triggers) * 25, 100)

        # Threat Intelligence: el primer link del mensaje contra URLhaus
        ti_urlhaus = threat_intel.check_url_urlhaus(urls[0]) if urls else {"available": False, "reason": "Sin URLs en el mensaje."}
        if ti_urlhaus.get("found"):
            urgency_score = min(urgency_score + 40, 100)

        is_smishing_probable = (
            urgency_score >= 50
            or (len(urls) > 0 and urgency_score >= 25)
            or ti_urlhaus.get("found", False)
        )

        return {
            "text": text,
            "urgency_score": urgency_score,
            "matched_triggers": matched_triggers,
            "extracted_urls": urls,
            "is_smishing_probable": is_smishing_probable,
            "threat_intel": {
                "urlhaus_first_url": ti_urlhaus
            }
        }

    @staticmethod
    def _is_blocked_ip(ip_str: str) -> bool:
        """True si esta IP no debe ser alcanzada por una petición del servidor
        (loopback, RFC1918, link-local -incluye metadata de nube 169.254.169.254-,
        multicast, reservada o sin especificar). Si no se puede ni parsear, se
        trata como bloqueada por seguridad (fail-closed)."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        return (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        )

    @staticmethod
    def _resolve_and_guard(hostname: str):
        """Resuelve el hostname y valida la IP ANTES de dejar que se intente
        cualquier conexión. Devuelve (ip_o_'No resoluble', motivo_de_bloqueo).
        motivo_de_bloqueo es "" si el destino está permitido."""
        if not hostname:
            return "No resoluble", ""
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            return "No resoluble", ""
        if ForensicAnalyzer._is_blocked_ip(ip):
            return ip, (
                f"Destino bloqueado: {ip} es una dirección privada/interna/reservada "
                "(protección anti-SSRF — Anzuelo no sigue URLs hacia redes internas)."
            )
        return ip, ""

    @staticmethod
    def analyze_url_chain(target_url: str) -> dict:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        hops = []
        final_url = target_url
        status_code = None
        ssrf_blocked = False
        resolved_ip = "No resoluble"

        current_url = target_url
        session = requests.Session()
        for hop_index in range(MAX_REDIRECTS + 1):
            hop_parsed = urlparse(current_url)
            hop_scheme = (hop_parsed.scheme or "").lower()
            hop_hostname = hop_parsed.hostname or ""

            if hop_scheme not in ALLOWED_URL_SCHEMES:
                hops.append({"error": f"Esquema no permitido: '{hop_scheme}'."})
                ssrf_blocked = True
                break

            # Se resuelve y valida UNA vez por salto (incluido el primero):
            # una URL pública puede redirigir (302) hacia una IP interna, y
            # eso hay que bloquearlo igual que el destino inicial.
            hop_ip, hop_block_reason = ForensicAnalyzer._resolve_and_guard(hop_hostname)
            resolved_ip = hop_ip
            if hop_block_reason:
                hops.append({"error": hop_block_reason})
                ssrf_blocked = True
                break

            try:
                resp = session.get(
                    current_url, allow_redirects=False, timeout=4,
                    headers={"User-Agent": "Mozilla/5.0 (Anzuelo-OSINT-Triage)"},
                )
            except Exception as e:
                hops.append({"error": str(e)})
                break

            status_code = resp.status_code
            final_url = current_url

            if status_code in (301, 302, 303, 307, 308) and hop_index < MAX_REDIRECTS:
                location = resp.headers.get("Location", "")
                hops.append({
                    "url": current_url,
                    "status_code": status_code,
                    "location": location,
                })
                if not location:
                    break
                current_url = urljoin(current_url, location)
                continue
            break

        # Threat Intelligence: URL final en VirusTotal/URLhaus, IP resuelta en
        # AbuseIPDB, edad del dominio. Solo se consulta sobre el último destino
        # VALIDADO como no-privado — nunca sobre el objetivo bloqueado.
        ti_vt_url = threat_intel.check_url_virustotal(final_url)
        ti_urlhaus = threat_intel.check_url_urlhaus(final_url)
        ti_abuseipdb = threat_intel.check_ip_abuseipdb(resolved_ip)
        ti_whois = threat_intel.check_domain_whois(hostname)

        total_redirects = sum(1 for h in hops if "location" in h)

        risk_score = 0
        if total_redirects > 0:
            risk_score += 20
        if resolved_ip in ("No resoluble", ""):
            risk_score += 15
        if ti_vt_url.get("found"):
            if ti_vt_url.get("malicious", 0) > 0:
                risk_score += 50
            elif ti_vt_url.get("suspicious", 0) > 0:
                risk_score += 20
        if ti_urlhaus.get("found"):
            risk_score += 60
        if ti_abuseipdb.get("found"):
            score = ti_abuseipdb.get("abuse_confidence_score", 0) or 0
            if score >= 50:
                risk_score += 30
            elif score >= 20:
                risk_score += 15
        if ti_whois.get("found"):
            age_days = ti_whois.get("age_days", 9999)
            if age_days < 30:
                risk_score += 40
            elif age_days < 180:
                risk_score += 20
        if ssrf_blocked:
            # Un intento de apuntar (directo o vía redirect) a una red interna
            # es en sí mismo un indicador fuerte — no lo tratamos como "sin datos".
            risk_score = max(risk_score, 80)
        risk_score = min(risk_score, 100)

        if ssrf_blocked:
            verdict = "Alto Riesgo (bloqueado: intento de acceso a red privada/interna — posible SSRF)"
        elif risk_score >= 60:
            verdict = "Alto Riesgo (URL maliciosa o IP comprometida)"
        else:
            verdict = "Bajo Riesgo / Sin coincidencias"

        return {
            "initial_url": target_url,
            "final_url": final_url,
            "hostname": hostname,
            "resolved_ip": resolved_ip,
            "status_code": status_code,
            "total_redirects": total_redirects,
            "hops_chain": hops,
            "blocked_ssrf": ssrf_blocked,
            "risk_score": risk_score,
            "verdict": verdict,
            "threat_intel": {
                "virustotal_url": ti_vt_url,
                "urlhaus": ti_urlhaus,
                "abuseipdb_ip": ti_abuseipdb,
                "whois_domain": ti_whois
            }
        }

    @staticmethod
    def decode_and_analyze_qr_image(file_bytes: bytes) -> dict:
        try:
            image = Image.open(io.BytesIO(file_bytes))
            
            if image.mode not in ("RGB", "L"):
                image = image.convert("RGB")

            decoded_objects = decode_qr(image)

            if not decoded_objects:
                return {
                    "success": False,
                    "error": "No se detectó ningún código QR legible en la imagen proporcionada."
                }

            payload = decoded_objects[0].data.decode("utf-8", errors="replace")
            qr_type = decoded_objects[0].type

            url_analysis = None
            if payload.strip().startswith(("http://", "https://")):
                url_analysis = ForensicAnalyzer.analyze_url_chain(payload.strip())

            return {
                "success": True,
                "type": qr_type,
                "payload": payload,
                "is_url": url_analysis is not None,
                "url_analysis": url_analysis
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Fallo al procesar la imagen: {str(e)}"
            }
