import psutil
import time

class ProcessMonitor:
    def __init__(self):
        self.running_pids = set()
        self._initialize_pids()

    def _initialize_pids(self):
        for proc in psutil.process_iter(['pid']):
            self.running_pids.add(proc.info['pid'])

    def check_new_processes(self):
        """
        Scans for new processes and returns their details (htop-style).
        """
        new_events = []
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'create_time']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                if pid not in self.running_pids:
                    # Capture htop-style info
                    info = {
                        "pid": pid,
                        "name": proc.info['name'],
                        "user": proc.info['username'],
                        "path": proc.info['exe'] or "Unknown",
                        "created": proc.info['create_time']
                    }
                    new_events.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.running_pids = current_pids
        return new_events

if __name__ == "__main__":
    monitor = ProcessMonitor()
    print("Monitoring for new processes... (ctrl+c to stop)")
    try:
        while True:
            new_procs = monitor.check_new_processes()
            for p in new_procs:
                print(f"NEW PROCESS: {p['name']} (PID: {p['pid']}) by {p['user']} at {p['path']}")
            time.sleep(2)
    except KeyboardInterrupt:
        pass
