import subprocess
import sys
import time
import os

def main():
    print("==================================================")
    print("   AIDS ThreatShield AI - Unified App Launcher    ")
    print("==================================================\n")

    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "aids-backend")
    frontend_dir = os.path.join(root_dir, "aids-frontend")

    print("🚀 [1/2] Starting FastAPI Backend (http://localhost:8000)...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
        cwd=backend_dir
    )

    time.sleep(1.5)

    print("🚀 [2/2] Starting Vite Frontend (http://localhost:5173)...")
    frontend_cmd = "npx.cmd vite" if os.name == "nt" else "npx vite"
    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=frontend_dir,
        shell=True
    )

    print("\n" + "="*50)
    print("  ✓ SUCCESS: Backend and Frontend are running!")
    print("  ----------------------------------------------")
    print("  - Backend API:  http://localhost:8000")
    print("  - Frontend UI:  http://localhost:5173")
    print("  - GUI Console:  python kali.py")
    print("  ----------------------------------------------")
    print("  Press Ctrl+C at any time to stop both servers.")
    print("="*50 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down backend and frontend services...")
        try:
            backend_proc.terminate()
            frontend_proc.terminate()
        except Exception:
            pass
        print("✓ All services stopped cleanly.")

if __name__ == "__main__":
    main()
