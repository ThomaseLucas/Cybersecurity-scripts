# Log file explanations:
# 1. Security: Tracks login attempts.
# 2. System: Tracks system events.
# 3. Application: Tracks application-specific events.

import win32evtlog
import win32evtlogutil
import win32con
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Check for administrative privileges
if not is_admin():
    print("This script requires administrative privileges. Restarting with elevated permissions...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit()

def parse_security_logs():
    # Open the Security log file
    server = 'localhost'  # Local computer
    logtype = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    log_handle = win32evtlog.OpenEventLog(server, logtype)

    events = []

    print("Scanning Security logs for Event ID 4625 (Failed Logons)...")
    
    total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
    print(f"Total records: {total_records}")

    while True:
        records = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if not records:
            break
        for record in records:
            # Filter for Event ID 4625 (Failed logon attempts)
            if record.EventID == 4625:
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
suspicious_events = parse_security_logs()

# Display results
if suspicious_events:
    print("\nSuspicious events found in Security logs:")
    for event in suspicious_events:
        print("-" * 50)
        print(f"Time: {event['Time']}")
        print(f"Source: {event['Source']}")
        print(f"Description: {event['Description']}")
else:
    print("No suspicious events found in Security logs.")

input("\nPress Enter to exit...")