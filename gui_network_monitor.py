import nmap
import threading
import ipaddress
import socket
import platform
import subprocess
import re
from datetime import datetime
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


def get_local_network():
    """
    Auto-detect the local network range based on the machine's IP address.
    Returns a CIDR notation string (e.g., '192.168.1.0/24')
    """
    try:
        # Get local IP by connecting to an external address (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Get subnet mask based on OS
        subnet_mask = get_subnet_mask(local_ip)

        # Calculate network address
        ip = ipaddress.IPv4Address(local_ip)
        mask = ipaddress.IPv4Address(subnet_mask)
        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)

        return str(network)
    except Exception as e:
        # Fallback to a common default
        print(f"Could not auto-detect network: {e}")
        return "192.168.1.0/24"


def get_subnet_mask(ip_address):
    """
    Get the subnet mask for the given IP address based on the operating system.
    """
    system = platform.system()

    try:
        if system == "Windows":
            # Use ipconfig on Windows
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            output = result.stdout

            # Find the section with our IP
            lines = output.split('\n')
            found_ip = False
            for i, line in enumerate(lines):
                if ip_address in line:
                    found_ip = True
                if found_ip and "Subnet Mask" in line:
                    mask = line.split(":")[-1].strip()
                    return mask

        elif system == "Linux" or system == "Darwin":  # Darwin is macOS
            # Use ip command on Linux or ifconfig on macOS
            if system == "Linux":
                result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
                output = result.stdout
                # Parse format like: inet 192.168.1.100/24
                match = re.search(rf"inet {re.escape(ip_address)}/(\d+)", output)
                if match:
                    prefix_len = int(match.group(1))
                    # Convert CIDR to subnet mask
                    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
            else:  # macOS
                result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                output = result.stdout
                # Parse ifconfig output
                lines = output.split('\n')
                found_ip = False
                for line in lines:
                    if ip_address in line and "inet " in line:
                        found_ip = True
                        match = re.search(r"netmask\s+0x([0-9a-fA-F]+)", line)
                        if match:
                            # Convert hex to dotted decimal
                            hex_mask = match.group(1)
                            mask_int = int(hex_mask, 16)
                            return socket.inet_ntoa(mask_int.to_bytes(4, 'big'))
    except Exception as e:
        print(f"Error getting subnet mask: {e}")

    # Default fallback to /24 network (255.255.255.0)
    return "255.255.255.0"


# -------------------------
# Threat / Risk Heuristics
# -------------------------

# Common risky ports (context: exposure on internal networks)
RISKY_PORTS = {
    21: ("FTP", "Clear-text auth; often misconfigured"),
    23: ("Telnet", "Insecure remote shell (clear-text)"),
    25: ("SMTP", "Mail service; can be abused if misconfigured"),
    53: ("DNS", "If unexpected on client, may be suspicious"),
    69: ("TFTP", "Insecure file transfer"),
    110: ("POP3", "Clear-text email retrieval (if not encrypted)"),
    139: ("NetBIOS", "Legacy Windows file sharing surface"),
    445: ("SMB", "Frequent target; lateral movement risk"),
    3389: ("RDP", "Brute-force target; remote admin exposure"),
    5900: ("VNC", "Remote control exposure"),
}

# Extra "admin/management" ports that are okay for routers/infra but notable:
MGMT_PORTS = {
    22: "SSH",
    80: "HTTP (admin panel)",
    443: "HTTPS (admin panel)",
    161: "SNMP",
    8080: "HTTP-alt (admin/proxy)",
    8443: "HTTPS-alt (admin)",
}


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Network/target cannot be empty.")

    if "*" in target:
        parts = target.split(".")
        if len(parts) == 4 and parts[3] == "*":
            cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            ipaddress.ip_network(cidr, strict=False)
            return cidr
        raise ValueError("Wildcard supported only like 172.16.0.*")

    if "/" in target:
        ipaddress.ip_network(target, strict=False)
        return target

    if "-" in target:
        return target

    ipaddress.ip_address(target)
    return target


def parse_ports(port_str: str) -> str:
    port_str = port_str.strip()
    if not port_str:
        raise ValueError("Ports cannot be empty.")
    allowed = set("0123456789,- ")
    if any(ch not in allowed for ch in port_str):
        raise ValueError("Ports must be numbers, commas, hyphens. Example: 1-1024 or 22,80,443")
    return port_str.replace(" ", "")


def evaluate_threat(open_ports: list[int], services: dict[int, str], os_guess: str) -> tuple[str, int, str]:
    """
    Returns: (Threat Level, Risk Score, Reasons)
    Heuristic (safe, academic): flags exposure + misconfiguration signals.
    """
    score = 0
    reasons = []

    open_set = set(open_ports)

    # 1) Risky ports open
    for p in sorted(open_set):
        if p in RISKY_PORTS:
            svc_name, why = RISKY_PORTS[p]
            score += 30
            reasons.append(f"Risky port open: {p}/{svc_name} ({why})")

    # 2) Too many open ports
    if len(open_ports) >= 10:
        score += 25
        reasons.append(f"High number of open ports: {len(open_ports)}")

    # 3) Legacy/insecure service names (best-effort from -sV output)
    for p, svc in services.items():
        low = (svc or "").lower()
        if "telnet" in low:
            score += 20
            reasons.append(f"Insecure service detected on port {p}: telnet")
        if "ftp" in low:
            score += 15
            reasons.append(f"Insecure service detected on port {p}: ftp")
        if "smb" in low or "microsoft-ds" in low:
            score += 15
            reasons.append(f"SMB-related service on port {p}")

    # 4) Unknown OS + management ports open -> medium risk
    if (not os_guess) or os_guess.strip().lower() == "unknown":
        mgmt_exposed = [p for p in open_ports if p in MGMT_PORTS]
        if mgmt_exposed:
            score += 15
            reasons.append(f"Unknown OS but management ports exposed: {', '.join(map(str, mgmt_exposed))}")

    # 5) Cap score for sanity
    score = min(score, 100)

    # Threat level bands
    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons = ["No obvious risky exposure detected (based on scanned ports/services)."]

    return level, score, " | ".join(reasons)


class NetworkMonitorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Device Monitor (Admin GUI) + Threat Detection")
        self.root.geometry("1350x740")

        self.scanner = nmap.PortScanner()
        self.devices = []
        self.scanning = False  # Track if scan is in progress
        self.cancel_scan = False  # Flag to cancel ongoing scan
        self.scan_thread = None  # Reference to current scan thread

        # Auto-detect local network
        self.detected_network = get_local_network()

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill="x")

        # Network info display
        info_frame = ttk.Frame(frm)
        info_frame.grid(row=0, column=0, columnspan=8, sticky="w", pady=(0, 8))

        ttk.Label(info_frame, text=f"Auto-detected network: {self.detected_network}",
                  font=("Segoe UI", 9, "bold"), foreground="green").pack(side="left")

        ttk.Button(info_frame, text="Refresh Network",
                   command=self.refresh_network).pack(side="left", padx=10)

        ttk.Label(frm, text="Network / Target:").grid(row=1, column=0, sticky="w")
        self.target_var = tk.StringVar(value=self.detected_network)
        ttk.Entry(frm, textvariable=self.target_var, width=26).grid(row=1, column=1, padx=6)

        ttk.Label(frm, text="Ports:").grid(row=1, column=2, sticky="w")
        self.ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(frm, textvariable=self.ports_var, width=18).grid(row=1, column=3, padx=6)

        self.os_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="OS detection (-O)", variable=self.os_var).grid(row=1, column=4, padx=8)

        self.sv_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Service/version (-sV)", variable=self.sv_var).grid(row=1, column=5, padx=8)

        self.btn_scan = ttk.Button(frm, text="Scan Network", command=self.start_scan_thread)
        self.btn_scan.grid(row=1, column=6, padx=6)

        self.btn_export = ttk.Button(frm, text="Export CSV", command=self.export_csv)
        self.btn_export.grid(row=1, column=7, padx=6)

        self.status_var = tk.StringVar(value="Ready. Click 'Scan Network' to start scanning your local network.")
        ttk.Label(frm, textvariable=self.status_var).grid(row=2, column=0, columnspan=8, sticky="w", pady=(6, 0))

        # Changed from horizontal to vertical orientation
        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        top = ttk.Frame(paned)
        bottom = ttk.Frame(paned)
        paned.add(top, weight=3)
        paned.add(bottom, weight=1)

        # Added Threat Level + Risk Score columns
        cols = (
            "IP", "MAC", "Vendor", "Status", "OS Guess", "Last Seen",
            "Open Ports", "Closed Ports", "Filtered Ports", "Threat Level", "Risk Score"
        )
        self.tree = ttk.Treeview(top, columns=cols, show="headings", height=15)

        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120, anchor="center")

        self.tree.column("IP", width=110, anchor="center")
        self.tree.column("MAC", width=150, anchor="center")
        self.tree.column("Vendor", width=160, anchor="center")
        self.tree.column("Status", width=70, anchor="center")
        self.tree.column("OS Guess", width=190, anchor="center")
        self.tree.column("Last Seen", width=150, anchor="center")
        self.tree.column("Open Ports", width=85, anchor="center")
        self.tree.column("Closed Ports", width=95, anchor="center")
        self.tree.column("Filtered Ports", width=105, anchor="center")
        self.tree.column("Threat Level", width=95, anchor="center")
        self.tree.column("Risk Score", width=80, anchor="center")

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_device)

        ttk.Label(bottom, text="Selected Device Details", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

        # Add scrollbar to detail text
        detail_frame = ttk.Frame(bottom)
        detail_frame.pack(fill="both", expand=True)

        self.detail_text = tk.Text(detail_frame, wrap="word", height=10, state="disabled",
                                   bg="#f0f0f0", cursor="arrow")
        self.detail_text.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(detail_frame, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")

    def start_scan_thread(self):
        # If already scanning, cancel it immediately
        if self.scanning:
            self.cancel_scan = True
            self._set_status("⏹ Scan cancelled!")
            # Force immediate termination by resetting state
            self.scanning = False
            self._enable_scan_button()
            return

        # Start new scan
        self.scanning = True
        self.cancel_scan = False
        self.btn_scan.config(text="Cancel Scan")

        # Clear previous results
        self.devices.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.config(state="disabled")

        # Start scan in background thread
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()

    def run_scan(self):
        try:
            # Quick exit if already cancelled
            if self.cancel_scan:
                return

            target = normalize_target(self.target_var.get())
            ports = parse_ports(self.ports_var.get())

            # Check cancel before discovery
            if self.cancel_scan:
                return

            # 1) Host discovery
            self._set_status(f"Discovering hosts on {target} ...")

            # Run discovery in try-except to catch interruptions
            try:
                self.scanner.scan(hosts=target, arguments='-sn')
            except:
                if self.cancel_scan:
                    return
                raise

            # Check if cancelled immediately after discovery
            if self.cancel_scan:
                return

            hosts = self.scanner.all_hosts()

            if not hosts:
                self._set_status("No hosts discovered. Try checking your network connection or firewall settings.")
                return

            # Check cancel before starting port scans
            if self.cancel_scan:
                return

            self._set_status(f"Discovered {len(hosts)} host(s). Scanning ports/services ...")

            # 2) Deep scan per host
            base_args = f"-sT -p {ports} -Pn -T4"
            if self.sv_var.get():
                base_args += " -sV"
            if self.os_var.get():
                base_args += " -O --osscan-guess"

            for idx, host in enumerate(hosts, start=1):
                # Check if cancelled before each host scan - IMMEDIATE EXIT
                if self.cancel_scan:
                    return

                self._set_status(f"Scanning {host} ({idx}/{len(hosts)}) ...")

                # Wrap scan in try-except for quick exit
                try:
                    self.scanner.scan(hosts=host, arguments=base_args)
                except:
                    if self.cancel_scan:
                        return
                    raise

                # Check again immediately after scan
                if self.cancel_scan:
                    return

                dev = self._build_device_record(host, ports)
                self.devices.append(dev)
                self._insert_device_row(dev)

            # Final check
            if self.cancel_scan:
                return

            self._set_status(f"✓ Scan complete! Found {len(self.devices)} device(s). Select a row for details.")
        except Exception as e:
            if not self.cancel_scan:
                self._set_status(f"Error during scan: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Scan error", str(e)))
        finally:
            # Always reset state and re-enable button
            self.scanning = False
            self.cancel_scan = False
            self.scan_thread = None
            self._enable_scan_button()

    def _build_device_record(self, host: str, ports_str: str) -> dict:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        mac = "Unknown"
        vendor = "Unknown"
        status = "unknown"
        os_guess = "Unknown"

        try:
            status = self.scanner[host].state()
            mac = self.scanner[host].get('addresses', {}).get('mac', 'Unknown')
            vendor = self.scanner[host].get('vendor', {}).get(mac, 'Unknown')

            osmatch = self.scanner[host].get('osmatch', [])
            if osmatch:
                os_guess = osmatch[0].get('name', 'Unknown')
        except Exception:
            pass

        open_ports: list[int] = []
        closed_ports: list[int] = []
        filtered_ports: list[int] = []
        services: dict[int, str] = {}
        port_details_lines: list[str] = []

        try:
            for proto in self.scanner[host].all_protocols():
                for p in sorted(self.scanner[host][proto].keys()):
                    info = self.scanner[host][proto][p]
                    state = info.get("state", "unknown")
                    name = info.get("name", "")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    extrainfo = info.get("extrainfo", "")

                    if state == "open":
                        open_ports.append(p)
                    elif state == "closed":
                        closed_ports.append(p)
                    elif state == "filtered":
                        filtered_ports.append(p)

                    svc = " ".join(x for x in [name, product, version, extrainfo] if x).strip()
                    if state == "open":
                        services[p] = svc

                    port_details_lines.append(f"{proto.upper():<4} {p:>5}  {state:<9}  {svc}")
        except Exception:
            port_details_lines.append("No port details (host may block probes or is not reachable).")

        threat_level, risk_score, reasons = evaluate_threat(open_ports, services, os_guess)

        dev = {
            "IP": host,
            "MAC": mac,
            "Vendor": vendor,
            "Status": status,
            "OS Guess": os_guess,
            "Last Seen": now,
            "Ports Scanned": ports_str,
            "Open Ports Count": str(len(open_ports)),
            "Closed Ports Count": str(len(closed_ports)),
            "Filtered Ports Count": str(len(filtered_ports)),
            "Threat Level": threat_level,
            "Risk Score": str(risk_score),
            "Threat Reasons": reasons,
            "Port Details": "\n".join(port_details_lines),
        }
        return dev

    def _insert_device_row(self, dev: dict):
        self.tree.insert("", "end", values=(
            dev["IP"],
            dev["MAC"],
            dev["Vendor"],
            dev["Status"],
            dev["OS Guess"],
            dev["Last Seen"],
            dev["Open Ports Count"],
            dev["Closed Ports Count"],
            dev["Filtered Ports Count"],
            dev["Threat Level"],
            dev["Risk Score"],
        ))

    def on_select_device(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx < 0 or idx >= len(self.devices):
            return

        dev = self.devices[idx]

        # Enable editing temporarily to update content
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", tk.END)

        self.detail_text.insert(tk.END, f"IP: {dev['IP']}\n")
        self.detail_text.insert(tk.END, f"MAC: {dev['MAC']}\n")
        self.detail_text.insert(tk.END, f"Vendor: {dev['Vendor']}\n")
        self.detail_text.insert(tk.END, f"Status: {dev['Status']}\n")
        self.detail_text.insert(tk.END, f"OS Guess: {dev['OS Guess']}\n")
        self.detail_text.insert(tk.END, f"Last Seen: {dev['Last Seen']}\n")
        self.detail_text.insert(tk.END, f"Ports Scanned: {dev['Ports Scanned']}\n\n")

        self.detail_text.insert(tk.END, f"Threat Level: {dev['Threat Level']}  (Score: {dev['Risk Score']})\n")
        self.detail_text.insert(tk.END, f"Reasons: {dev['Threat Reasons']}\n\n")

        self.detail_text.insert(tk.END, "Port Details:\n")
        self.detail_text.insert(tk.END, dev["Port Details"])

        # Disable editing to make it read-only
        self.detail_text.config(state="disabled")

    def export_csv(self):
        if not self.devices:
            messagebox.showinfo("Export", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save device list as CSV"
        )
        if not path:
            return

        fieldnames = [
            "IP", "MAC", "Vendor", "Status", "OS Guess", "Last Seen",
            "Ports Scanned", "Open Ports Count", "Closed Ports Count", "Filtered Ports Count",
            "Threat Level", "Risk Score", "Threat Reasons", "Port Details"
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.devices)

        messagebox.showinfo("Export", f"Exported to:\n{path}")

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _enable_scan_button(self):
        """Safely re-enable the scan button on the main thread"""

        def enable():
            self.btn_scan.config(state="normal", text="Scan Network")

        self.root.after(0, enable)

    def refresh_network(self):
        """Refresh the auto-detected network"""
        # Cancel any ongoing scan immediately
        if self.scanning:
            self.cancel_scan = True
            self.scanning = False
            self._enable_scan_button()

        # Refresh the network
        self.detected_network = get_local_network()
        self.target_var.set(self.detected_network)
        self._set_status(f"Network refreshed: {self.detected_network}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()