
import argparse
import glob
import os
import re
import time
import sys
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'storage', 'logs')

def get_latest_log():
    files = glob.glob(os.path.join(LOG_DIR, "rija-auth-*.log"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def get_log_by_date(date_str):
    return os.path.join(LOG_DIR, f"rija-auth-{date_str}.log")

def parse_line(line):
    # [2026-01-25 14:30:45] env.LEVEL: Message {context}
    match = re.search(r'\[(.*?)\] (.*?)\.(.*?): (.*)', line)
    if match:
        return {
            'timestamp': match.group(1),
            'environment': match.group(2),
            'level': match.group(3),
            'content': match.group(4)
        }
    return None

def process_file(filename, args):
    if not os.path.exists(filename):
        print(f"Error: Log file {filename} not found.")
        return

    print(f"Viewing log file: {filename}")
    print("-" * 80)

    with open(filename, 'r', encoding='utf-8') as f:
        # If follow, seek to end first? No, tail usually shows last lines.
        # But for simple viewer, cat or tail.
        
        if args.follow:
            f.seek(0, 2) # Go to end
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                display_line(line, args)
        else:
            for line in f:
                display_line(line, args)

def display_line(line, args):
    parsed = parse_line(line)
    if not parsed:
        print(line, end='')
        return

    if args.level and parsed['level'] != args.level.upper():
        return
        
    if args.search and args.search not in line:
        return

    # Colorize if possible (simple)
    prefix = f"[{parsed['timestamp']}] {parsed['level']}:"
    content = parsed['content']
    
    print(f"{prefix} {content}")

def main():
    parser = argparse.ArgumentParser(description="View RijanAuth Logs")
    parser.add_argument('--date', help="Date YYYY-MM-DD", default=None)
    parser.add_argument('--level', help="Filter level (INFO, ERROR, DEBUG)", default=None)
    parser.add_argument('--search', help="Search term", default=None)
    parser.add_argument('-f', '--follow', action='store_true', help="Follow log output (tail -f)")
    args = parser.parse_args()
    
    filename = get_latest_log()
    if args.date:
        filename = get_log_by_date(args.date)
        
    if not filename:
        print("No log files found.")
        return
        
    try:
        process_file(filename, args)
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()
