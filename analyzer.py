import argparse
import json

LOGFILE_PATH = "/Users/adibgharibe/Desktop/Arbeit/It-sec_Projekte/Security_Log_Analyzer/test_auth.log"
JSON_OUTPUT_PATH = "/Users/adibgharibe/Desktop/Arbeit/It-sec_Projekte/Security_Log_Analyzer/report.json"

def time_to_seconds(t: str) -> int:
    # "HH:MM:SS" -> Sekunden seit 00:00:00
    h, m, s = t.split(":")
    return int(h) * 3600 + int(m) * 60 + int(s)

def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer: SSH brute-force detection")
    parser.add_argument("--top", type=int, default=10, help="Show top N IPs by total fails")
    parser.add_argument("--min", type=int, default=1, help="Only show IPs with at least N total fails")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds (default: 60)")
    parser.add_argument("--threshold", type=int, default=5, help="Fails within window to trigger alert (default: 5)")
    parser.add_argument("--out", default="report.json", help="Write JSON report to this file")
    args = parser.parse_args()

    counts = {}

    ip_times = {}

    alerts = {}

    try:
        f = open(LOGFILE_PATH, "r", encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        print("Log file not found:")
        print(LOGFILE_PATH)
        return

    for line in f:
        if "Failed password" not in line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        t_str = parts[2]

        if "from" not in parts:
            continue
        ip = parts[parts.index("from") + 1]

       
        counts[ip] = counts.get(ip, 0) + 1

    
        t_sec = time_to_seconds(t_str)
        times = ip_times.get(ip, [])
        times.append(t_sec)


        while times and (t_sec - times[0] > args.window):
            times.pop(0)

        ip_times[ip] = times

       
        if len(times) >= args.threshold:
            if ip not in alerts:
                alerts[ip] = (t_str, len(times))
            else:
                first_time, max_in_window = alerts[ip]
                if len(times) > max_in_window:
                    alerts[ip] = (first_time, len(times))

    f.close()

   
    print("\n=== Brute-force alerts (window-based) ===")
    if not alerts:
        print(f"No alerts. (threshold={args.threshold} within window={args.window}s)")
    else:

        for ip, (first_time, max_in_window) in sorted(alerts.items(), key=lambda x: x[1][1], reverse=True):
            print(f"ALERT: Possible SSH brute-force from {ip} (max {max_in_window} fails within {args.window}s, first at {first_time})")

   
    print("\n=== Failed SSH logins by IP (total) ===")
    shown = 0
    for ip, n in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        if n >= args.min:
            print(f"{ip:15}  {n}")
            shown += 1
            if shown >= args.top:
                break

        if shown == 0:
            print(f"No IPs found with >= {args.min} total failed attempts.")


    JSON_OUTPUT_PATH = "/Users/adibgharibe/Desktop/Arbeit/It-sec_Projekte/Security_Log_Analyzer/report.json"

    report = {
        "settings": {
            "logfile_path": LOGFILE_PATH,
            "window_seconds": args.window,
            "threshold": args.threshold,
            "top": args.top,
            "min_total": args.min,
        },
        "alerts": [
            {
                "ip": ip,
                "first_time": first_time,
                "max_fails_in_window": max_in_window,
            }
            for ip, (first_time, max_fails_in_window) in sorted(
                alerts.items(), key=lambda x: x[1][1], reverse=True
            )
        ],
        "totals": [
            {"ip": ip, "total_failed_logins": n}
            for ip, n in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ],
    }

    with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print(f"\n JSON report written to: {JSON_OUTPUT_PATH}")


        

if __name__ == "__main__":
    main()
