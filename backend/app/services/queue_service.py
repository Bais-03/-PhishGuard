"""
Queue Service - Simplified version for file uploads
"""
import asyncio
from typing import Optional, Dict

class AnalysisQueue:
    """Simple in-memory queue for async processing"""
    
    def __init__(self):
        self.tasks = {}
    
    async def enqueue(self, task_id: str, email_content: str, metadata: Dict = None):
        self.tasks[task_id] = {
            "task_id": task_id,
            "status": "queued",
            "email_content": email_content,
            "metadata": metadata or {}
        }
        return True
    
    async def get_status(self, task_id: str) -> Optional[Dict]:
        return self.tasks.get(task_id)


class WorkerService:
    """Simple worker service"""
    
    def __init__(self, queue: AnalysisQueue):
        self.queue = queue
        self.running = False
    
    async def start(self):
        self.running = True
        print("Worker started")
    
    async def stop(self):
        self.running = False
        print("Worker stopped")


_queue_instance = None
_worker_instance = None

async def get_analysis_queue() -> AnalysisQueue:
    global _queue_instance
    if _queue_instance is None:
        _queue_instance = AnalysisQueue()
    return _queue_instance

async def get_worker() -> WorkerService:
    global _worker_instance
    if _worker_instance is None:
        queue = await get_analysis_queue()
        _worker_instance = WorkerService(queue)
    return _worker_instance
