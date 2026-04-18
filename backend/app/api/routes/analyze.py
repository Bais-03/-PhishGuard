"""
Unified Analysis API Endpoint
Supports: raw text, file upload, JSON payload
Backward compatible with existing /analyze/email endpoint
"""
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from typing import Optional
import uuid
from app.services.email_parser import parse_email_input
from app.core.pipeline import run_pipeline
from app.models.schemas import AnalysisResult, EmailInput
from app.api.dependencies import get_analysis_queue

router = APIRouter(prefix="/analyze", tags=["Analysis"])

@router.post("/email", response_model=AnalysisResult)
async def analyze_email_raw(data: EmailInput):
    """
    EXISTING ENDPOINT - PRESERVED FOR BACKWARD COMPATIBILITY
    Analyze email from raw text
    """
    if not data.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email cannot be empty")
    
    result = await run_pipeline(data.raw_email, use_playwright=False)
    return result


@router.post("/email/upload", response_model=AnalysisResult)
async def analyze_email_file(
    file: UploadFile = File(..., description=".eml file to analyze"),
    async_mode: bool = Form(False, description="Process asynchronously")
):
    """
    NEW ENDPOINT - Upload .eml file for analysis
    """
    # Validate file
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    
    # Read file content
    try:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    # Parse email
    try:
        email_content = parse_email_input(content, input_type="file")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Process synchronously or asynchronously
    if async_mode:
        # Queue for background processing
        task_id = str(uuid.uuid4())
        queue = await get_analysis_queue()
        await queue.enqueue(task_id, email_content)
        return AnalysisResult(
            score=0,
            verdict="PENDING",
            flags=[],
            reasons=["Analysis queued. Check /status/{task_id} for results"],
            input_type="email",
            cache_hit=False,
            duration_ms=0
        )
    
    # Synchronous processing (backward compatible)
    result = await run_pipeline(email_content, use_playwright=False)
    return result


@router.post("/email/forward", response_model=dict)
async def analyze_forwarded_email(
    email_content: str = Form(...),
    sender: str = Form(None),
    recipient: str = Form(None)
):
    """
    NEW ENDPOINT - Handle forwarded emails from webhook
    Returns task ID for async processing
    """
    try:
        parsed_content = parse_email_input(email_content, input_type="forwarded")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Always async for forwarded emails (could be high volume)
    task_id = str(uuid.uuid4())
    queue = await get_analysis_queue()
    await queue.enqueue(task_id, parsed_content, metadata={
        "sender": sender,
        "recipient": recipient,
        "source": "forwarded_email"
    })
    
    return {
        "status": "queued",
        "task_id": task_id,
        "message": "Email queued for analysis. Results will be sent to your email."
    }


@router.get("/status/{task_id}", response_model=dict)
async def get_analysis_status(task_id: str):
    """
    NEW ENDPOINT - Check status of async analysis
    """
    queue = await get_analysis_queue()
    status = await queue.get_status(task_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return status