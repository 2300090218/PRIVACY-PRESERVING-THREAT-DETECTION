"""
Privacy-Preserving Threat Detection Platform - Unified Platform Orchestrator
Launches and monitors both the FastAPI backend and Next.js frontend concurrently.

Usage:
    python run_platform.py               # Launch full platform (Backend + Frontend)
    python run_platform.py --verify      # Launch platform and run automated system verification
    python run_platform.py --backend     # Launch only FastAPI backend
    python run_platform.py --frontend    # Launch only Next.js frontend
    python run_platform.py --retrain     # Retrain baseline ML model before launch
"""

import os
import sys
import time
import signal
import shutil
import argparse
import subprocess
import urllib.request
import urllib.error

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")
BACKEND_HEALTH_URL = "http://127.0.0.1:8000/api/health"

def print_banner():
    banner = r"""
=============================================================================
  PRIVACY-PRESERVING COLLABORATIVE THREAT DETECTION PLATFORM
  Dual Heuristic/ML Engine  *  Salted HMAC Minimization  *  DP-FedAvg
=============================================================================
"""
    print(banner)

def check_prerequisites():
    print("[1/4] Checking environment & runtime prerequisites...")
    # 1. Python
    py_ver = sys.version_info
    if py_ver.major < 3 or (py_ver.major == 3 and py_ver.minor < 10):
        print(f"Error: Python 3.10+ required, found Python {py_ver.major}.{py_ver.minor}")
        sys.exit(1)
    print(f"  [OK] Python {py_ver.major}.{py_ver.minor}.{py_ver.micro}")

    # 2. Node.js & npm
    node_cmd = shutil.which("node")
    npm_cmd = shutil.which("npm")
    if not node_cmd or not npm_cmd:
        print("  [WARN] Node.js or npm not detected in PATH. Frontend launch may fail.")
    else:
        try:
            node_v = subprocess.check_output([node_cmd, "--version"], text=True).strip()
            print(f"  [OK] Node.js {node_v}")
        except Exception:
            pass

    # 3. Baseline ML Model
    model_path = os.path.join(ROOT_DIR, "ml", "models", "baseline_rf.joblib")
    if not os.path.exists(model_path):
        print("  [INFO] Baseline model not found. Automatically training baseline...")
        from ml.training.train_baseline import train_baseline_model
        train_baseline_model(data_dir=os.path.join(ROOT_DIR, "ml", "datasets"), models_dir=os.path.join(ROOT_DIR, "ml", "models"))
    else:
        print("  [OK] Baseline Random Forest model verified.")

def wait_for_backend(timeout: float = 25.0) -> bool:
    print("  Waiting for FastAPI backend to respond at http://127.0.0.1:8000/api/health ...", end="", flush=True)
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with urllib.request.urlopen(BACKEND_HEALTH_URL, timeout=1.5) as res:
                if res.status == 200:
                    print(" [READY]")
                    return True
        except Exception:
            time.sleep(0.8)
            print(".", end="", flush=True)
    print(" [TIMEOUT]")
    return False

def main():
    parser = argparse.ArgumentParser(description="Privacy-Preserving Threat Detection Platform Runner")
    parser.add_argument("--verify", action="store_true", help="Run end-to-end verification suite against live backend")
    parser.add_argument("--backend", action="store_true", help="Launch only FastAPI backend")
    parser.add_argument("--frontend", action="store_true", help="Launch only Next.js frontend")
    parser.add_argument("--retrain", action="store_true", help="Retrain baseline model before starting")
    args = parser.parse_args()

    print_banner()

    if args.retrain:
        print("[Retrain] Training fresh baseline Random Forest model...")
        from ml.training.train_baseline import train_baseline_model
        train_baseline_model(data_dir=os.path.join(ROOT_DIR, "ml", "datasets"), models_dir=os.path.join(ROOT_DIR, "ml", "models"))

    check_prerequisites()

    processes = []

    def shutdown(signum=None, frame=None):
        print("\n\n[Shutdown] Terminating platform processes...")
        for name, proc in processes:
            try:
                print(f"  Stopping {name} (PID {proc.pid})...")
                proc.terminate()
                proc.wait(timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("[Shutdown] All platform services stopped. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Launch Backend
    if not args.frontend:
        print("[2/4] Starting FastAPI Backend on http://127.0.0.1:8000 ...")
        backend_log = open(os.path.join(ROOT_DIR, "backend_platform.log"), "w", encoding="utf-8")
        backend_cmd = [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"]
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=ROOT_DIR,
            stdout=backend_log,
            stderr=subprocess.STDOUT,
            text=True
        )
        processes.append(("FastAPI Backend", backend_proc))

    # Wait for backend readiness
    if not args.frontend:
        backend_ready = wait_for_backend()
        if not backend_ready:
            print("Warning: Backend did not respond in time. Proceeding anyway...")

    # Launch Frontend
    if not args.backend:
        print("[3/4] Starting Next.js Frontend on http://localhost:3000 ...")
        frontend_log = open(os.path.join(ROOT_DIR, "frontend_platform.log"), "w", encoding="utf-8")
        npm_cmd = shutil.which("npm") or "npm.cmd"
        frontend_proc = subprocess.Popen(
            [npm_cmd, "run", "dev"],
            cwd=FRONTEND_DIR,
            stdout=frontend_log,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True if sys.platform == "win32" else False
        )
        processes.append(("Next.js Frontend", frontend_proc))

    print("\n[4/4] Platform services launched successfully!")
    print("""
+---------------------------------------------------------------------------+
|               PLATFORM SERVICES ACTIVE & READY TO USE                     |
+---------------------------------------------------------------------------+
  * Web Dashboard:          http://localhost:3000
  * REST API & Endpoints:   http://127.0.0.1:8000
  * Interactive API Docs:   http://127.0.0.1:8000/docs
  * WebSocket Stream:       ws://127.0.0.1:8000/ws
  * Default Credentials:    admin / AdminPass123!
+---------------------------------------------------------------------------+
  Press Ctrl+C to gracefully stop all services.
""")

    # If --verify was specified, run the verification script
    if args.verify:
        print("[Verify] Running automated end-to-end system verification...")
        time.sleep(2.0)
        from scripts.verify_system import run_verification
        success = run_verification()
        if not success:
            print("\n[Error] Verification failed!")
        else:
            print("\n[Success] Verification passed completely!")

    # Stream logs
    try:
        while True:
            # Check if any process died
            for name, proc in processes:
                poll = proc.poll()
                if poll is not None:
                    print(f"\n[Warning] Service '{name}' exited with code {poll}")
                    log_file = os.path.join(ROOT_DIR, "backend_platform.log" if "FastAPI" in name else "frontend_platform.log")
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, "r", encoding="utf-8") as f:
                                print(f.read()[-500:])
                        except Exception:
                            pass
                    shutdown()
            time.sleep(1.0)
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
