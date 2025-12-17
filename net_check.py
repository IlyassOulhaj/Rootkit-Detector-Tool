# net_hunter.py

import os
from typing import List

def hex_to_decimal_port(hex_port: str) -> int:
    """
    Converts a hexadecimal port string (e.g., '0050') into its decimal equivalent (e.g., 80).
    """
    try:
        # The port is often stored in the 4th column of /proc/net/tcp
        return int(hex_port, 16)
    except ValueError:
        return 0

def scan_net(suspicious_port_list: List[int] = None) -> bool:
    """
    Scans the /proc/net/tcp file for open listening ports.
    
    Returns:
        True if a suspicious port is detected, False otherwise.
    """
    print("📢 Ali: Running Network Scan (Reading /proc/net/tcp)...")
    
    # Default list including the suspicious port 4444 mentioned in the assignment
    if suspicious_port_list is None:
        suspicious_port_list = [4444]

    net_file_path = "/proc/net/tcp"
    
    if not os.path.exists(net_file_path):
        print(f"   [Error] File not found: {net_file_path}. Cannot complete network scan.")
        # This will return False on non-Linux systems or if the file is missing
        return False

    suspicious_ports_found = []
    
    try:
        with open(net_file_path, 'r') as f:
            # Skip the header line
            lines = f.readlines()[1:] 
            
            for line in lines:
                fields = line.strip().split()
                
                # The local address/port is the 2nd column (index 1)
                # The connection state ('st') is the 4th column (index 3)
                if len(fields) < 4:
                    continue
                
                local_addr_port = fields[1]
                state = fields[3]
                
                # Separate IP and Port: Example '0100007F:0016'
                if ':' in local_addr_port:
                    _, hex_port_str = local_addr_port.split(':')
                    decimal_port = hex_to_decimal_port(hex_port_str)
                    
                    # State '0A' (10) represents TCP_LISTEN
                    if state == '0A': 
                        if decimal_port in suspicious_port_list:
                            suspicious_ports_found.append(decimal_port)
                            print(f"   [🚨 Suspicious Port] Port {decimal_port} (0x{hex_port_str}) is LISTENING.")

        if suspicious_ports_found:
            return True
        else:
            print("   [RESULT] Ali found no suspicious listening ports.")
            return False

    except Exception as e:
        print(f"   [Fatal Error] An exception occurred during network scan: {e}")
        return False