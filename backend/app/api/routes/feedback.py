from fastapi import APIRouter
import structlog

from app.models.schemas import FalsePositiveFeedbackInput

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])
logger = structlog.get_logger()


@router.post("/false-positive", response_model=dict)
async def report_false_positive(data: FalsePositiveFeedbackInput):
    """
    Optional endpoint used by the extension to report phishing false positives.
    This is intentionally isolated from the main analysis flow.
    """
    logger.info(
        "false_positive_report_received",
        url=data.url,
        verdict=data.verdict,
        score=data.score,
        source=data.source,
        reported_at=data.reported_at.isoformat()
    )

    return {
        "status": "accepted",
        "url": data.url,
        "verdict": data.verdict,
        "score": data.score,
        "source": data.source
    }
