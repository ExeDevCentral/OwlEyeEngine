import psutil
import socket

class NetworkMonitor:
    def __init__(self):
        self.connections = set()
        self._initialize_connections()

    def _get_conn_key(self, conn):
        return (conn.laddr, conn.raddr, conn.status)

    def _initialize_connections(self):
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr: # Only track established/remote connections
                self.connections.add(self._get_conn_key(conn))

    def check_new_connections(self):
        """
        Detects new network entries, identifying the 'Entry Point'.
        """
        new_entries = []
        current_connections = set()
        
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr:
                continue
                
            key = self._get_conn_key(conn)
            current_connections.add(key)
            
            if key not in self.connections:
                # Identify potential entry point
                remote_ip = conn.raddr.ip
                local_port = conn.laddr.port
                
                entry_point = f"Network:{remote_ip} -> LocalPort:{local_port}"
                
                # Check for common Cisco-managed segments or unknown IPs
                # (Conceptual: in a real Cisco environment, we'd compare against known subnets)
                
                info = {
                    "type": "CONNECTION",
                    "remote": f"{remote_ip}:{conn.raddr.port}",
                    "local": f"{conn.laddr.ip}:{local_port}",
                    "entry_point": entry_point
                }
                new_entries.append(info)
        
        self.connections = current_connections
        return new_entries

if __name__ == "__main__":
    monitor = NetworkMonitor()
    print("Monitoring for new connections... (ctrl+c to stop)")
    try:
        while True:
            new_conns = monitor.check_new_connections()
            for c in new_conns:
                print(f"NEW ENTRY: {c['remote']} via {c['entry_point']}")
            import time
            time.sleep(2)
    except KeyboardInterrupt:
        pass
