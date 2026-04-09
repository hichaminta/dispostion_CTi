import subprocess
import os
import sys
import time

def run_platform():
    # 1. Start Backend
    print("Starting Backend (app.main with fix)...")
    backend_process = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=os.path.join(os.getcwd(), "backend")
    )
    
    # 2. Wait a bit for backend to start
    time.sleep(2)
    
    # 3. Start Frontend
    print("Starting Frontend (Vite)...")
    frontend_process = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=os.path.join(os.getcwd(), "frontend"),
        shell=True # Needed for npm on windows
    )
    
    print("\n" + "="*40)
    print("CTI Pipeline Platform is running!")
    print("Backend: http://localhost:8000")
    print("Frontend: http://localhost:5173")
    print("="*40 + "\n")
    
    try:
        while True:
            time.sleep(1)
            if backend_process.poll() is not None:
                print("Backend stopped unexpectedly.")
                break
            if frontend_process.poll() is not None:
                print("Frontend stopped unexpectedly.")
                break
    except KeyboardInterrupt:
        print("\nStopping platform...")
        backend_process.terminate()
        frontend_process.terminate()

if __name__ == "__main__":
    run_platform()
