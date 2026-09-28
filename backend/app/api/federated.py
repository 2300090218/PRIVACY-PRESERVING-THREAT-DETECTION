"""
Federated Learning API Endpoints
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import TrainingRound
from backend.app.schemas.all_schemas import (
    FederatedStatusResponse, FederatedStartRequest, FederatedRoundResponse
)
from backend.app.federated.server import fl_server

router = APIRouter(prefix="/api/federated", tags=["Federated Learning"])

@router.get("/status", response_model=FederatedStatusResponse)
async def get_federated_status():
    return fl_server.get_status()

import logging

logger = logging.getLogger(__name__)

@router.post("/start")
async def start_federated_round(db: AsyncSession = Depends(get_db)):
    """Triggers an authentic federated learning round across local client partitions."""
    try:
        result = await fl_server.execute_federated_round(db=db, actor="ADMIN")
        if not isinstance(result, dict):
            raise ValueError("Federated server returned invalid round result.")
        return {
            "status": "COMPLETED",
            "round": result.get("round"),
            "model_version": result.get("model_version"),
            "metrics": {
                "accuracy": result.get("accuracy", 0.0),
                "precision": result.get("precision", 0.0),
                "recall": result.get("recall", 0.0),
                "f1": result.get("f1", 0.0),
                "loss": result.get("loss", 0.0),
                "training_time": result.get("training_time", 0.0),
                "clients_completed": result.get("clients_completed", 0)
            },
            "differential_privacy": result.get("differential_privacy")
        }
    except (ValueError, RuntimeError) as e:
        logger.warning(f"[FL API] Federated round rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[FL API] Federated round unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Federated round could not be completed.")

@router.post("/stop")
async def stop_federated_training():
    fl_server.is_training = False
    return {"message": "Federated training stopped"}

@router.get("/rounds", response_model=List[FederatedRoundResponse])
async def get_training_rounds(db: AsyncSession = Depends(get_db)):
    stmt = select(TrainingRound).order_by(desc(TrainingRound.round_num))
    result = await db.execute(stmt)
    return result.scalars().all()
