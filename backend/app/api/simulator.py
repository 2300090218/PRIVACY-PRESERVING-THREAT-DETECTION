"""
Traffic Simulator API Router
Provides endpoints to monitor, toggle, and trigger simulated attack scenarios
and federated rounds on-demand for live demonstrations and testing.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.services.traffic_simulator import traffic_simulator

router = APIRouter(prefix="/api/simulator", tags=["Traffic Simulator"])

class TriggerAttackRequest(BaseModel):
    attack_type: Optional[str] = "Brute Force"

@router.get("/status")
async def get_simulator_status():
    """Returns current runtime status and counters of the traffic simulator."""
    return traffic_simulator.get_status()

@router.post("/toggle")
async def toggle_simulator():
    """Toggles the background traffic generator on or off."""
    if traffic_simulator.is_running:
        await traffic_simulator.stop()
        return {"status": "STOPPED", "message": "Traffic simulator stopped."}
    else:
        await traffic_simulator.start()
        return {"status": "STARTED", "message": "Traffic simulator started."}

@router.post("/start")
async def start_simulator():
    await traffic_simulator.start()
    return {"status": "STARTED", "message": "Traffic simulator started."}

@router.post("/stop")
async def stop_simulator():
    await traffic_simulator.stop()
    return {"status": "STOPPED", "message": "Traffic simulator stopped."}

@router.post("/trigger-attack")
async def trigger_simulated_attack(req: TriggerAttackRequest):
    """Triggers an instantaneous attack event (Brute Force, Port Scan, Backdoor / C2, DDoS Flood)."""
    valid_attacks = ["Brute Force", "Port Scan", "Backdoor / C2", "DDoS Flood"]
    attack = req.attack_type or "Brute Force"
    if attack not in valid_attacks:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Must be one of: {valid_attacks}")

    await traffic_simulator._generate_and_process_event(attack_type=attack)
    return {
        "status": "ATTACK_TRIGGERED",
        "attack_type": attack,
        "message": f"Simulated {attack} successfully generated and broadcast."
    }

@router.post("/trigger-federated-round")
async def trigger_simulated_fl_round():
    """Triggers an immediate decentralized federated learning round."""
    result = await traffic_simulator.trigger_federated_round()
    return {
        "status": "FEDERATED_ROUND_COMPLETED",
        "round_metrics": result
    }
