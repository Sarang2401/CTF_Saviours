import re

def parse_access_log(log_filepath, keyword=None):
    """
    Parses a web server access log for common patterns or a specific keyword.
    Assumes a common log format (IP - - [datetime] "METHOD /path HTTP/1.1" status size "referrer" "user-agent").
    """
    print(f"--- Parsing Log File: {log_filepath} ---")
    parsed_entries = []
    
    # Example regex for Apache common log format (simplified)
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)')

    try:
        with open(log_filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = log_pattern.match(line)
                if match:
                    ip, timestamp, request, status, size = match.groups()
                    entry = {
                        "line_num": line_num,
                        "ip": ip,
                        "timestamp": timestamp,
                        "request": request,
                        "status": int(status),
                        "size": int(size) if size != '-' else 0,
                        "raw_line": line.strip()
                    }
                    if keyword and keyword in line:
                        parsed_entries.append(entry)
                        print(f"  [Match] Line {line_num}: {line.strip()}")
                    elif not keyword: # If no keyword, print all
                        parsed_entries.append(entry)
                        print(f"  Line {line_num}: IP={ip}, Status={status}, Request='{request}'")
                elif keyword and keyword in line:
                     # Catch lines that don't fit the pattern but contain the keyword
                    print(f"  [Partial Match] Line {line_num}: {line.strip()}")
                else:
                    # print(f"  [Skipped] Line {line_num}: Does not match pattern or keyword.")
                    pass # Don't print skipped lines by default for cleaner output
        
        print(f"\nTotal entries parsed (with keyword '{keyword}' if specified): {len(parsed_entries)}")
        return parsed_entries
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_filepath}")
        return []
    except Exception as e:
        print(f"Error parsing log file: {e}")
        return []

if __name__ == "__main__":
    # Create a dummy log file for testing
    dummy_log_content = """192.168.1.1 - - [18/Jul/2025:10:30:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://referrer.com" "Mozilla/5.0"
192.168.1.2 - - [18/Jul/2025:10:30:05 +0000] "POST /login.php HTTP/1.1" 401 56 "http://site.com/login" "User-Agent/1.0"
10.0.0.5 - - [18/Jul/2025:10:30:10 +0000] "GET /admin/panel.php HTTP/1.1" 302 0 "-" "CTF_BOT_SCANNER"
192.168.1.3 - - [18/Jul/2025:10:30:15 +0000] "GET /images/logo.png HTTP/1.1" 200 5000 "-" "Mozilla/5.0"
This line has a potential vulnerability: password_exposed=true
"""
    with open("access.log", "w") as f:
        f.write(dummy_log_content)

    parse_access_log("access.log")
    parse_access_log("access.log", keyword="admin")
    parse_access_log("access.log", keyword="password_exposed")
    
    os.remove("access.log")