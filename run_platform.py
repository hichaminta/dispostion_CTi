import subprocess
import os
import sys
import time
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"

def run_platform():
    local_ip = get_local_ip()
    # 1. Start Backend
    print(f"Starting Backend (app.main on 0.0.0.0)...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    backend_process = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=os.path.join(base_dir, "backend")
    )
    
    # 2. Wait a bit for backend to start
    time.sleep(2)
    
    # 3. Start Frontend
    print(f"Starting Frontend (Vite --host)...")
    frontend_process = subprocess.Popen(
        ["npm", "run", "dev", "--", "--host"],
        cwd=os.path.join(base_dir, "frontend"),
        shell=True # Needed for npm on windows
    )
    
    print("\n" + "="*50)
    print("CTI Pipeline Platform is running!")
    print(f"Local access:    http://localhost:5173")
    print(f"Network access:  http://{local_ip}:5173")
    print("-" * 50)
    print(f"Backend API:     http://{local_ip}:8000")
    print("="*50 + "\n")
    
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
        
        # Graceful cleanup
        def safe_stop(proc, name):
            if proc.poll() is None:
                print(f"Stopping {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"Force killing {name}...")
                    proc.kill()
        
        safe_stop(backend_process, "Backend")
        safe_stop(frontend_process, "Frontend")
        print("Platform stopped.")

if __name__ == "__main__":
    run_platform()
