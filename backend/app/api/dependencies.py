"""
Shared API Dependencies
"""
from app.services.queue_service import get_analysis_queue

async def get_analysis_queue_dep():
    return await get_analysis_queue()
