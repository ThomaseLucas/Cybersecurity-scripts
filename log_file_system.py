# Log file explanations:
# 1. Security: Tracks login attempts.
# 2. System: Tracks system events.
# 3. Application: Tracks application-specific events.

import win32evtlog
import win32evtlogutil
import win32con
import ctypes
import sys

import win32evtlog
import win32evtlogutil
import ctypes
import sys

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Restart the script with elevated privileges if not run as admin
if not is_admin():
    print("This script requires administrative privileges. Restarting with elevated permissions...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit()

def parse_system_logs():
    """Parse System logs for suspicious events."""
    server = 'localhost'  # Local machine
    logtype = 'System'  # System log
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    log_handle = win32evtlog.OpenEventLog(server, logtype)

    # List of suspicious event IDs
    suspicious_event_ids = [7000, 7011, 7023, 7034, 41, 6008]
    events = []

    print("Scanning System logs for suspicious events...")

    while True:
        records = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if not records:
            break

        for record in records:
            if record.EventID in suspicious_event_ids:
                try:
                    event_details = {
                        "Event ID": record.EventID,
                        "Time": record.TimeGenerated.Format(),
                        "Source": record.SourceName,
                        "Description": win32evtlogutil.SafeFormatMessage(record, logtype)
                    }
                    events.append(event_details)
                except Exception as e:
                    print(f"Error reading event description: {e}")
                    continue

    win32evtlog.CloseEventLog(log_handle)
    return events

# Run the parser
suspicious_events = parse_system_logs()

# Display results
if suspicious_events:
    print("\nSuspicious events found in System logs:")
    for event in suspicious_events:
        print("-" * 50)
        print(f"Event ID: {event['Event ID']}")
        print(f"Time: {event['Time']}")
        print(f"Source: {event['Source']}")
        print(f"Description: {event['Description']}")
else:
    print("No suspicious events found in System logs.")

# Pause before exiting
input("\nPress Enter to exit...")
