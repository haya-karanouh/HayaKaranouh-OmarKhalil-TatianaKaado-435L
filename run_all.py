"""Start all nine Flask services as independent local processes."""

import signal
import subprocess
import sys

from common.config import PROJECT_ROOT, SERVICE_PORTS


def main():
    processes = []
    try:
        for service, port in SERVICE_PORTS.items():
            command = [sys.executable, "-m", f"services.{service}.app"]
            process = subprocess.Popen(command, cwd=PROJECT_ROOT)
            processes.append((service, port, process))
            print(f"Started {service} on http://127.0.0.1:{port}", flush=True)
        for _, _, process in processes:
            process.wait()
    except KeyboardInterrupt:
        print("Stopping services...", flush=True)
    finally:
        for _, _, process in processes:
            if process.poll() is None:
                process.terminate()
        for _, _, process in processes:
            if process.poll() is None:
                process.wait()


if __name__ == "__main__":
    main()
