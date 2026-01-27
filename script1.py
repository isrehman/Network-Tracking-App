import subprocess
import time
import datetime

# Ping funksiyası
def ping_ip(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        return result.returncode == 0
    except Exception as e:
        return False

# Nmap funksiyası
def nmap_scan(ip):
    try:
        result = subprocess.run(["nmap", "-sP", ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        return result.stdout
    except Exception as e:
        return f"Nmap xətası: {e}"

# Real-time monitorinq funksiyası
def real_time_monitor(ip_list, interval=30):
    print(f"--- IP monitorinq sistemi başladı ---")
    print(f"Yenilənmə intervalı: {interval} saniyə\n")

    while True:
        print(f"\n=== Yeni yoxlanış: {datetime.datetime.now()} ===")

        for ip in ip_list:
            print(f"\nIP: {ip}")

            # Ping nəticəsi
            is_alive = ping_ip(ip)
            if is_alive:
                print("Ping: Aktiv ✓")
            else:
                print("Ping: Cavab yoxdur ✗")

            # Nmap nəticəsi
            print("Nmap nəticəsi:")
            print(nmap_scan(ip))

        print(f"\n--- {interval} saniyə gözlənilir... ---")
        time.sleep(interval)


# ==== İSTİFADƏ ====
ip_list = [
    "192.168.100.1",
    "192.168.100.10",
    "8.8.8.8"
]

# 30-60 saniyə interval (burada 30 saniyə)
real_time_monitor(ip_list, interval=30)
