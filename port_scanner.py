import nmap
import tkinter as tk
from tkinter import messagebox
import schedule
import time
import threading
import csv
import json

def scan_ports(target, ports, scan_type, output_format):
    """Scans specified ports on the target IP or hostname with various options and saves the results."""
    nm = nmap.PortScanner()
    result = {}
    
    try:
        print(f"Starting scan on {target} for ports: {ports}")
        
        # Construct the scan arguments based on user input
        scan_args = "-O -sV -A --traceroute" if scan_type == "Aggressive Scan" else "-O -sV"
        
        # Perform the scan with OS, version, and other options
        nm.scan(hosts=target, ports=ports, arguments=scan_args)
        
        for host in nm.all_hosts():
            result[host] = {
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os": nm[host].get('osmatch', 'Unknown'),
                "ports": {}
            }
            for protocol in nm[host].all_protocols():
                for port in nm[host][protocol].keys():
                    port_info = nm[host][protocol][port]
                    result[host]["ports"][port] = {
                        "state": port_info['state'],
                        "service": port_info.get('name', 'Unknown')
                    }
                    
        if output_format == "CSV":
            save_to_csv(result)
        elif output_format == "JSON":
            save_to_json(result)
        
        messagebox.showinfo("Scan Complete", "Scan completed and results saved.")
        
    except Exception as e:
        print(f"Error: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

def save_to_csv(result):
    """Saves scan results to a CSV file."""
    with open("scan_results.csv", mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Host", "Port", "State", "Service"])
        
        for host, details in result.items():
            for port, port_info in details["ports"].items():
                writer.writerow([host, port, port_info['state'], port_info['service']])

def save_to_json(result):
    """Saves scan results to a JSON file."""
    with open("scan_results.json", mode='w') as file:
        json.dump(result, file, indent=4)

def schedule_scan(target, ports, scan_type, output_format, interval):
    """Schedules a scan at a specified interval."""
    schedule.every(interval).minutes.do(lambda: scan_ports(target, ports, scan_type, output_format))

    while True:
        schedule.run_pending()
        time.sleep(1)

def start_scan_thread(target, ports, scan_type, output_format):
    """Runs the scan in a separate thread."""
    scan_thread = threading.Thread(target=scan_ports, args=(target, ports, scan_type, output_format))
    scan_thread.start()

def run_gui():
    """Runs the Tkinter GUI for user input and options."""
    def start_scan():
        target = target_entry.get()
        ports = ports_entry.get()
        scan_type = scan_type_var.get()
        output_format = output_format_var.get()

        if not target or not ports:
            messagebox.showerror("Input Error", "Target and Ports are required.")
            return

        if schedule_check_var.get():
            interval = int(interval_entry.get())
            threading.Thread(target=schedule_scan, args=(target, ports, scan_type, output_format, interval)).start()
        else:
            start_scan_thread(target, ports, scan_type, output_format)

    # Create GUI window
    root = tk.Tk()
    root.title("Nmap Port Scanner")

    # Target and Ports Input
    tk.Label(root, text="Target (IP or Hostname):").pack()
    target_entry = tk.Entry(root, width=30)
    target_entry.pack()

    tk.Label(root, text="Ports (e.g., 22,80,443 or 1-1000):").pack()
    ports_entry = tk.Entry(root, width=30)
    ports_entry.pack()

    # Scan Type
    scan_type_var = tk.StringVar(value="Aggressive Scan")
    tk.Label(root, text="Select Scan Type:").pack()
    tk.Radiobutton(root, text="Aggressive Scan", variable=scan_type_var, value="Aggressive Scan").pack()
    tk.Radiobutton(root, text="Standard Scan", variable=scan_type_var, value="Standard Scan").pack()

    # Output Format
    output_format_var = tk.StringVar(value="CSV")
    tk.Label(root, text="Select Output Format:").pack()
    tk.Radiobutton(root, text="CSV", variable=output_format_var, value="CSV").pack()
    tk.Radiobutton(root, text="JSON", variable=output_format_var, value="JSON").pack()

    # Schedule Option
    schedule_check_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Schedule scan every X minutes", variable=schedule_check_var).pack()

    tk.Label(root, text="Interval in minutes:").pack()
    interval_entry = tk.Entry(root, width=10)
    interval_entry.pack()

    # Start Scan Button
    start_button = tk.Button(root, text="Start Scan", command=start_scan)
    start_button.pack()

    # Run GUI
    root.mainloop()

if __name__ == "__main__":
    run_gui()
