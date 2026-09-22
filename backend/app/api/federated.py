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

@router.post("/start")
async def start_federated_round(db: AsyncSession = Depends(get_db)):
    """Triggers an authentic federated learning round across local client partitions."""
    try:
        result = await fl_server.execute_federated_round(db=db, actor="ADMIN")
        return {
            "status": "COMPLETED",
            "round": result["round"],
            "model_version": result["model_version"],
            "metrics": {
                "accuracy": result["accuracy"],
                "precision": result["precision"],
                "recall": result["recall"],
                "f1": result["f1"],
                "loss": result["loss"],
                "training_time": result["training_time"],
                "clients_completed": result["clients_completed"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_federated_training():
    fl_server.is_training = False
    return {"message": "Federated training stopped"}

@router.get("/rounds", response_model=List[FederatedRoundResponse])
async def get_training_rounds(db: AsyncSession = Depends(get_db)):
    stmt = select(TrainingRound).order_by(desc(TrainingRound.round_num))
    result = await db.execute(stmt)
    return result.scalars().all()
