import nmap
import csv
from datetime import datetime

scanner = nmap.PortScanner()
NETWORK = "192.168.1.0/24"

print("[+] Network scan started...")
scanner.scan(hosts=NETWORK, arguments='-sn -PR')

devices = []

for host in scanner.all_hosts():
    device = {
        "IP": host,
        "Status": scanner[host].state(),
        "MAC": scanner[host]['addresses'].get('mac', 'Unknown'),
        "Vendor": scanner[host]['vendor'].get(
            scanner[host]['addresses'].get('mac', ''), 'Unknown'
        ),
        "Last Seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    devices.append(device)

print(f"[+] {len(devices)} devices discovered.\n")

print("{:<16} {:<18} {:<10} {:<20} {:<20}".format(
    "IP", "MAC", "Status", "Vendor", "Last Seen"))

for d in devices:
    print("{:<16} {:<18} {:<10} {:<20} {:<20}".format(
        d["IP"], d["MAC"], d["Status"], d["Vendor"], d["Last Seen"]))

if devices:
    with open("network_devices.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=devices[0].keys())
        writer.writeheader()
        writer.writerows(devices)
    print("\n[+] CSV export successful.")
else:
    print("\n[!] No devices detected.")
