import re
import socket
import email
from email import policy
from urllib.parse import urlparse
import dns.resolver
import requests

class ForensicAnalyzer:

    @staticmethod
    def analyze_email_headers(raw_headers: str) -> dict:
        msg = email.message_from_string(raw_headers, policy=policy.default)
        
        from_header = msg.get("From", "Desconocido")
        to_header = msg.get("To", "Desconocido")
        subject = msg.get("Subject", "Sin asunto")
        date_header = msg.get("Date", "")
        received_hops = msg.get_all("Received", [])

        # Extraer dominio del remitente
        domain = ""
        match_email = re.search(r"@([\w.-]+)", from_header)
        if match_email:
            domain = match_email.group(1).strip(">")

        # Chequeo DNS real de SPF y DMARC
        spf_status = "NOT_FOUND"
        dmarc_status = "NOT_FOUND"
        mx_records = []

        if domain:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0

            # SPF
            try:
                txt_answers = resolver.resolve(domain, "TXT")
                for rdata in txt_answers:
                    txt_str = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if txt_str.startswith("v=spf1"):
                        spf_status = f"DETECTED: {txt_str[:50]}..."
                        break
            except Exception:
                spf_status = "FAIL_OR_NONE"

            # DMARC
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_answers:
                    txt_str = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if txt_str.startswith("v=DMARC1"):
                        dmarc_status = f"DETECTED: {txt_str[:50]}..."
                        break
            except Exception:
                dmarc_status = "FAIL_OR_NONE"

            # MX
            try:
                mx_answers = resolver.resolve(domain, "MX")
                mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
            except Exception:
                pass

        # Veredicto de riesgo
        risk_score = 0
        if "FAIL" in spf_status or spf_status == "NOT_FOUND":
            risk_score += 40
        if "FAIL" in dmarc_status or dmarc_status == "NOT_FOUND":
            risk_score += 40
        if not mx_records:
            risk_score += 20

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
            "risk_score": min(risk_score, 100),
            "verdict": "Alto Riesgo (Spoofing probable)" if risk_score >= 60 else "Bajo Riesgo / Alineado"
        }

    @staticmethod
    def analyze_sms(text: str) -> dict:
        triggers = [
            "urgente", "bloqueo", "cuenta", "inmediato", "banco", "suspensión", 
            "multa", "afip", "correo", "paquete", "premio", "seguridad", "clave", "token"
        ]
        text_lower = text.lower()
        matched_triggers = [t for t in triggers if t in text_lower]

        # Extraer enlaces
        urls = re.findall(r'(https?://[^\s]+)', text)

        urgency_score = min(len(matched_triggers) * 25, 100)

        return {
            "text": text,
            "urgency_score": urgency_score,
            "matched_triggers": matched_triggers,
            "extracted_urls": urls,
            "is_smishing_probable": urgency_score >= 50 or (len(urls) > 0 and urgency_score >= 25)
        }

    @staticmethod
    def analyze_url_chain(target_url: str) -> dict:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        # Resolución IP
        resolved_ip = ""
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip = "No resoluble"

        # Seguimiento de saltos HTTP
        hops = []
        final_url = target_url
        status_code = None

        try:
            session = requests.Session()
            res = session.get(target_url, allow_redirects=True, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Anzuelo-OSINT-Triage)"})
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

        return {
            "initial_url": target_url,
            "final_url": final_url,
            "hostname": hostname,
            "resolved_ip": resolved_ip,
            "status_code": status_code,
            "total_redirects": len(hops),
            "hops_chain": hops
        }
