"""
Client Management API Endpoints
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.schemas.all_schemas import (
    ClientRegisterRequest, ClientHeartbeatRequest, ClientResponse
)
from backend.app.services.client_service import client_service

router = APIRouter(prefix="/api/clients", tags=["Clients"])

@router.post("", response_model=ClientResponse)
@router.post("/register", response_model=ClientResponse)
async def register_client(req: ClientRegisterRequest, db: AsyncSession = Depends(get_db)):
    return await client_service.register_client(
        db=db,
        client_id=req.client_id,
        name=req.name,
        ip_address=req.ip_address,
        model_version=req.model_version
    )

@router.get("", response_model=List[ClientResponse])
async def list_clients(db: AsyncSession = Depends(get_db)):
    return await client_service.list_clients(db)

@router.get("/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str, db: AsyncSession = Depends(get_db)):
    client = await client_service.get_client_by_id(db, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client

@router.post("/{client_id}/heartbeat", response_model=ClientResponse)
async def client_heartbeat(
    client_id: str,
    req: ClientHeartbeatRequest,
    db: AsyncSession = Depends(get_db)
):
    client = await client_service.process_heartbeat(
        db=db,
        client_id=client_id,
        status=req.status,
        training_status=req.training_status,
        local_metrics=req.local_metrics
    )
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client
