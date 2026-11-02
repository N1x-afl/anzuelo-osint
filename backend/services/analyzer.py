import io
import re
import socket
import email
from email import policy
from urllib.parse import urlparse
from PIL import Image
from pyzbar.pyzbar import decode as decode_qr
import dns.resolver
import requests

from backend.services import threat_intel

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
                "virustotal_domain": ti_domain
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

        # Threat Intelligence: el primer link del mensaje contra URLhaus (sin API key)
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
    def analyze_url_chain(target_url: str) -> dict:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        resolved_ip = ""
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip = "No resoluble"

        hops = []
        final_url = target_url
        status_code = None

        try:
            session = requests.Session()
            res = session.get(target_url, allow_redirects=True, timeout=4, headers={"User-Agent": "Mozilla/5.0 (Anzuelo-OSINT-Triage)"})
            for resp in res.history:
                hops.append({
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("Location", "")
                })
            final_url = res.url
            status_code = res.status_code
        except Exception as e:
            hops.append({"error": str(e)})

        # Threat Intelligence: URL final en VirusTotal/URLhaus, IP resuelta en AbuseIPDB
        ti_vt_url = threat_intel.check_url_virustotal(final_url)
        ti_urlhaus = threat_intel.check_url_urlhaus(final_url)
        ti_abuseipdb = threat_intel.check_ip_abuseipdb(resolved_ip)

        risk_score = 0
        if len(hops) > 1:
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
        risk_score = min(risk_score, 100)

        return {
            "initial_url": target_url,
            "final_url": final_url,
            "hostname": hostname,
            "resolved_ip": resolved_ip,
            "status_code": status_code,
            "total_redirects": len(hops),
            "hops_chain": hops,
            "risk_score": risk_score,
            "verdict": "Alto Riesgo (URL maliciosa o IP comprometida)" if risk_score >= 60 else "Bajo Riesgo / Sin coincidencias",
            "threat_intel": {
                "virustotal_url": ti_vt_url,
                "urlhaus": ti_urlhaus,
                "abuseipdb_ip": ti_abuseipdb
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
