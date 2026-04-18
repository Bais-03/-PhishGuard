"""
Webhook endpoints for SendGrid and Mailgun integration
"""
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from app.services.email_receiver import get_email_receiver
from app.services.queue_service import get_analysis_queue
import uuid
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/webhook", tags=["Email Webhook"])

@router.post("/sendgrid")
async def sendgrid_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receive forwarded email from SendGrid Inbound Parse
    """
    try:
        form_data = await request.form()
        payload = dict(form_data)
        
        receiver = await get_email_receiver()
        parsed = await receiver.process_sendgrid_webhook(payload)
        
        # Queue for async processing
        task_id = str(uuid.uuid4())
        queue = await get_analysis_queue()
        await queue.enqueue(task_id, parsed["raw_email"], metadata={
            "sender": parsed["sender"],
            "source": "sendgrid"
        })
        
        # Send acknowledgment (will be processed by background task)
        background_tasks.add_task(
            send_analysis_acknowledgment,
            parsed["sender"],
            task_id
        )
        
        return {"status": "queued", "task_id": task_id}
        
    except Exception as e:
        logger.error("sendgrid_webhook_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mailgun")
async def mailgun_webhook(request: Request):
    """
    Receive forwarded email from Mailgun Webhook
    """
    try:
        form_data = await request.form()
        payload = dict(form_data)
        
        receiver = await get_email_receiver()
        parsed = await receiver.process_mailgun_webhook(payload)
        
        # Queue for async processing
        task_id = str(uuid.uuid4())
        queue = await get_analysis_queue()
        await queue.enqueue(task_id, parsed["raw_email"], metadata={
            "sender": parsed["sender"],
            "source": "mailgun"
        })
        
        return {"status": "queued", "task_id": task_id}
        
    except Exception as e:
        logger.error("mailgun_webhook_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


async def send_analysis_acknowledgment(user_email: str, task_id: str):
    """
    Send acknowledgment email to user
    (Implement with your email service)
    """
    # TODO: Implement email sending via SMTP/SendGrid/Mailgun
    logger.info("analysis_queued", user_email=user_email, task_id=task_id)