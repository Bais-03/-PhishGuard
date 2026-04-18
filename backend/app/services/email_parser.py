"""
Email Parser Service - Simplified version
"""
import email
from email.header import decode_header

class UnifiedEmailParser:
    
    @staticmethod
    def parse_from_string(raw_content: str) -> dict:
        msg = email.message_from_string(raw_content)
        return UnifiedEmailParser._extract_email_data(msg)
    
    @staticmethod
    def parse_from_file(file_content: bytes, filename: str) -> dict:
        msg = email.message_from_bytes(file_content)
        return UnifiedEmailParser._extract_email_data(msg)
    
    @staticmethod
    def _extract_email_data(msg) -> dict:
        headers = {}
        for key in ['From', 'Reply-To', 'To', 'Subject', 'Date']:
            val = msg.get(key, "")
            if val:
                headers[key] = val
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='replace')
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='replace')
        
        return {
            "headers": headers,
            "body_text": body,
            "raw_content": msg.as_string()
        }


def parse_email_input(raw_input, input_type: str = "string") -> str:
    parser = UnifiedEmailParser()
    
    if input_type == "string":
        data = parser.parse_from_string(raw_input)
    elif input_type == "file":
        data = parser.parse_from_file(raw_input, "file.eml")
    else:
        data = parser.parse_from_string(raw_input)
    
    return data.get("raw_content", str(raw_input))
