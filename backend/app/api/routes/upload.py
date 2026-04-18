"""
File Upload Endpoints - SIMPLIFIED VERSION
"""
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.core.pipeline import run_pipeline
from app.models.schemas import AnalysisResult

router = APIRouter(prefix="/upload", tags=["File Upload"])

@router.post("/eml", response_model=AnalysisResult)
async def upload_eml(file: UploadFile = File(...)):
    """
    Upload and analyze .eml file
    """
    # Validate file extension
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    
    # Read file content
    try:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    # Decode email content
    try:
        email_content = content.decode('utf-8', errors='replace')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode email: {str(e)}")
    
    # Run analysis
    try:
        result = await run_pipeline(email_content, use_playwright=False)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")