"""
Safe Test Mode API Endpoints
Provides controlled synthetic attack injection through the full real detection and privacy pipeline.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.services.test_runner import run_synthetic_security_test, continuous_monitor

router = APIRouter(prefix="/api/test", tags=["Test Mode"])

@router.post("/run")
async def execute_security_test(
    scenario_idx: Optional[int] = Query(None, ge=0, le=5),
    db: AsyncSession = Depends(get_db)
):
    """
    Executes a safe synthetic security test scenario through the full pipeline:
    Validation -> Privacy Engine -> Rule Engine -> ML Engine -> Risk Engine -> Database -> Alert -> WebSocket.
    """
    result = await run_synthetic_security_test(db, scenario_idx=scenario_idx)
    return result

@router.post("/continuous/start")
async def start_continuous_monitoring(
    interval: float = Query(3.0, ge=1.0, le=60.0, description="Interval in seconds between scan injections")
):
    """
    Starts background continuous security telemetry monitoring.
    Injects randomized scenarios on the given interval and streams live alerts & detections over WebSocket.
    """
    return continuous_monitor.start(interval_seconds=interval)

@router.post("/continuous/stop")
async def stop_continuous_monitoring():
    """
    Stops background continuous security telemetry monitoring.
    """
    return continuous_monitor.stop()

@router.get("/continuous/status")
async def get_continuous_monitoring_status():
    """
    Returns active monitoring status, scan count, and latest test execution details.
    """
    return continuous_monitor.get_status()

