import nmap

def scan_ports(target, ports):
    """Scans specified ports on the target IP or hostname with OS and version detection, aggressive scan, and traceroute."""
    nm = nmap.PortScanner()
    
    print(f"Starting scan on {target} for ports: {ports}")
    try:
        # Perform the scan with advanced features (OS, version detection, aggressive scan, and traceroute)
        nm.scan(hosts=target, ports=ports, arguments="-O -sV -A --traceroute")
        
        with open("scan_results.txt", "w") as f:
            f.write(f"Scan results for {target}:\n")
            
            for host in nm.all_hosts():
                f.write(f"\nHost: {host} ({nm[host].hostname()})\n")
                f.write(f"State: {nm[host].state()}\n")
                
                # OS detection
                if 'osclass' in nm[host]:
                    f.write(f"OS Detection: {nm[host]['osclass']}\n")
                if 'osmatch' in nm[host]:
                    f.write(f"OS Match: {nm[host]['osmatch']}\n")
                
                # Traceroute information
                if 'hostnames' in nm[host]:
                    f.write(f"Traceroute: {nm[host]['hostnames']}\n")
                
                # Protocol and port information
                for protocol in nm[host].all_protocols():
                    f.write(f"\nProtocol: {protocol}\n")
                    ports = nm[host][protocol].keys()
                    for port in sorted(ports):
                        port_info = nm[host][protocol][port]
                        f.write(f"Port: {port}, State: {port_info['state']}, Service: {port_info.get('name', 'Unknown')}\n")
                
                # Version Detection
                if 'versions' in nm[host]:
                    f.write(f"\nService Version Info: {nm[host]['versions']}\n")
                
                # Display additional information from aggressive scan
                if 'script' in nm[host]:
                    f.write(f"Scripts: {nm[host]['script']}\n")
        
        print(f"Scan complete! Results saved to 'scan_results.txt'")
        
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("Nmap Port Scanner with OS and Service Detection, Aggressive Scan, and Traceroute")
    
    # Prompt for target(s) (multiple hosts allowed)
    target = input("Enter target(s) (comma-separated for multiple targets, or IP range): ").strip()
    
    # Check if targets are provided
    if not target:
        print("Target(s) are required!")
        return
    
    ports = input("Enter ports (e.g., 22,80,443 or 1-1000): ").strip()
    
    if not ports:
        print("Ports are required!")
        return
    
    # Perform scan
    scan_ports(target, ports)

if __name__ == "__main__":
    main()
