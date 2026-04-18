"""
Email Receiver Service - Placeholder
"""
import structlog

logger = structlog.get_logger()

class EmailReceiverService:
    async def process_sendgrid_webhook(self, payload: dict):
        return {"raw_email": "", "sender": "", "source": "sendgrid"}
    
    async def process_mailgun_webhook(self, payload: dict):
        return {"raw_email": "", "sender": "", "source": "mailgun"}

_email_receiver = None

async def get_email_receiver():
    global _email_receiver
    if _email_receiver is None:
        _email_receiver = EmailReceiverService()
    return _email_receiver
