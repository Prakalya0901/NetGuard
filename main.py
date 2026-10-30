
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address

# Security thresholds
PORT_THRESHOLD = 5
FAILED_THRESHOLD = 5
TRAFFIC_THRESHOLD = 10
TIME_WINDOW = 60


def analyze_logs(filename):

    events = []

    try:
        with open(filename, "r", newline="") as file:

            reader = csv.DictReader(file)

            required = {
                "timestamp", "src_ip", "dst_ip",
                "dst_port", "protocol", "status"
            }

            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                print("Invalid CSV format!")
                return

            for row in reader:

                try:
                    ip_address(row["src_ip"])
                    ip_address(row["dst_ip"])

                    port = int(row["dst_port"])

                    if not 1 <= port <= 65535:
                        raise ValueError("Invalid port")

                    time = datetime.strptime(
                        row["timestamp"], "%Y-%m-%d %H:%M:%S"
                    )

                    events.append({
                        "time": time,
                        "src": row["src_ip"],
                        "dst": row["dst_ip"],
                        "port": port,
                        "status": row["status"].upper()
                    })

                except ValueError:
                    print("Invalid record skipped:", row)

    except FileNotFoundError:
        print("File not found!")
        return

    if not events:
        print("No valid network events found!")
        return

    # Store network information
    ip_ports = defaultdict(set)
    failed_attempts = defaultdict(int)
    ip_events = defaultdict(list)

    for event in events:

        src = event["src"]

        ip_ports[src].add(event["port"])
        ip_events[src].append(event["time"])

        if event["status"] == "FAIL":
            failed_attempts[src] += 1

    alerts = []

    # 1. Port scan detection
    for ip, ports in ip_ports.items():

        if len(ports) >= PORT_THRESHOLD:
            alerts.append(
                f"[PORT SCAN] {ip} accessed {len(ports)} ports"
            )

    # 2. Brute force detection
    for ip, count in failed_attempts.items():

        if count >= FAILED_THRESHOLD:
            alerts.append(
                f"[BRUTE FORCE] {ip} had {count} failed attempts"
            )

    # 3. Traffic spike detection
    for ip, times in ip_events.items():

        times.sort()
        left = 0

        for right in range(len(times)):

            while times[right] - times[left] > timedelta(seconds=TIME_WINDOW):
                left += 1

            count = right - left + 1

            if count >= TRAFFIC_THRESHOLD:
                alerts.append(
                    f"[TRAFFIC SPIKE] {ip} generated "
                    f"{count} events within 60 seconds"
                )
                break

    # Display report
    print("\n========== NETGUARD REPORT ==========")

    print("Total network events:", len(events))
    print("Unique source IPs:", len(ip_events))

    if alerts:

        print("\nSUSPICIOUS ACTIVITIES DETECTED:\n")

        for alert in alerts:
            print(alert)

    else:
        print("\nNo suspicious activities detected.")

    # Save report
    with open("security_alerts.txt", "w") as file:

        file.write("NETGUARD SECURITY REPORT\n\n")

        for alert in alerts:
            file.write(alert + "\n")

        if not alerts:
            file.write("No suspicious activities detected.")

    print("\nReport saved successfully!")


if __name__ == "__main__":

    print("NETGUARD - NETWORK INTRUSION DETECTION SYSTEM")

    filename = input("\nEnter CSV file name: ")

    analyze_logs(filename)
