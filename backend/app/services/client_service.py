"""
Client Management Service
Encapsulates registration, heartbeat updates, state tracking, and auditing for distributed security clients.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.models.all_models import Client
from backend.app.websocket.manager import ws_manager
from backend.app.services.audit_service import log_audit

class ClientService:
    async def register_client(
        self,
        db: AsyncSession,
        client_id: str,
        name: str,
        ip_address: Optional[str] = None,
        model_version: Optional[str] = "global-v1"
    ) -> Client:
        stmt = select(Client).where(Client.client_id == client_id)
        result = await db.execute(stmt)
        client = result.scalars().first()

        if client:
            client.name = name
            client.status = "ONLINE"
            client.last_seen = datetime.now(timezone.utc)
            if ip_address:
                client.ip_address = ip_address
        else:
            client = Client(
                client_id=client_id,
                name=name,
                status="ONLINE",
                ip_address=ip_address,
                model_version=model_version or "global-v1"
            )
            db.add(client)

        await db.flush()
        await log_audit(
            db, actor=client_id, action="CLIENT_REGISTERED",
            resource="client", resource_id=client_id,
            metadata={"ip_address": ip_address, "name": name}
        )
        await ws_manager.broadcast("client.updated", {
            "client_id": client.client_id,
            "name": client.name,
            "status": client.status,
            "model_version": client.model_version
        })
        return client

    async def list_clients(self, db: AsyncSession) -> List[Client]:
        stmt = select(Client).order_by(desc(Client.created_at))
        result = await db.execute(stmt)
        return result.scalars().all()

    async def get_client_by_id(self, db: AsyncSession, client_id: str) -> Optional[Client]:
        stmt = select(Client).where(Client.client_id == client_id)
        result = await db.execute(stmt)
        return result.scalars().first()

    async def process_heartbeat(
        self,
        db: AsyncSession,
        client_id: str,
        status: str = "ONLINE",
        training_status: Optional[str] = "IDLE",
        local_metrics: Optional[Dict[str, Any]] = None
    ) -> Optional[Client]:
        client = await self.get_client_by_id(db, client_id)
        if not client:
            return None

        client.last_seen = datetime.now(timezone.utc)
        client.status = status
        if training_status:
            client.training_status = training_status
        if local_metrics:
            client.local_metrics = local_metrics

        await db.flush()
        await ws_manager.broadcast("client.updated", {
            "client_id": client.client_id,
            "status": client.status,
            "training_status": client.training_status
        })
        return client

client_service = ClientService()
