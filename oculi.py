#!/usr/bin/env python3
# TODO: Make it into a nmap wrapper.

import argparse
import concurrent.futures
import csv
import io
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "exploit_db.json")

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GREY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner_art():
    print(f"{CYAN}{BOLD}")
    print(r"      .=%@@@%=.       ")
    print(r"     -%@@ . @@%-      OCULI VULNERABILITY SCANNER")
    print(r"    :#@@ (o) @@#:     v1.0 // Multithreaded Vulnerability Scanner")
    print(r"     -%@@ . @@%-      ")
    print(r"      '=%@@@%='       ")
    print(f"{RESET}")


def get_args():
    parser = argparse.ArgumentParser(description="Python Vulnerability Scanner - Intermediate/Advanced Final Project")
    parser.add_argument("-t", "--target", help="Target IP Address or Hostname", required=True)
    parser.add_argument("-p", "--ports",
                        help="Ports to scan: '-p 80,443' OR '-p-' for all ports. Defaults to Nmap's Top 1000.", required=False)
    parser.add_argument("-s", "--speed", help="Scan Speed (1-5). 5 is fastest. Default: 3", type=int, default=3,
                        choices=[1, 2, 3, 4, 5])
    parser.add_argument("-o", "--output", help="Output results to a file", required=False)
    parser.add_argument("-u", "--update", help="Update Exploit Database from Exploit-DB", action="store_true")
    args = parser.parse_args()
    return args


def get_scan_config(speed):
    if speed == 1:
        return 10, 5.0  # Threads, Timeout
    elif speed == 2:
        return 50, 2.0
    elif speed == 3:
        return 100, 1.0  # Balanced
    elif speed == 4:
        return 300, 0.7  # Aggressive
    elif speed == 5:
        return 500, 0.5  # Insane
    return 100, 1.0


def parse_ports(port_arg):
    if port_arg:
        if port_arg == '-':
            # 65535 total ports
            return range(1, 65536)  # Range object
        elif "-" in port_arg:
            ports = port_arg.split('-')
            return range(int(ports[0]), int(ports[1]) + 1)
        else:
            return [int(p) for p in port_arg.split(',')]
    else:
        # Nmap's Statistical Top 1000 Ports
        top_1000_str = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
        parsed_ports = []
        for segment in top_1000_str.split(','):
            if '-' in segment:
                start, end = segment.split('-')
                parsed_ports.extend(range(int(start), int(end) + 1))
            else:
                parsed_ports.append(int(segment))
        return parsed_ports


def parse_banner(banner):
    if not banner:
        return None

    # 1. Check for "Server:" explicitly (Common for HTTP)
    if "Server:" in banner:
        try:
            # Find the exact line containing "Server:"
            for line in banner.splitlines():
                if "Server:" in line:
                    # Split by "Server:" and take the second part
                    return line.split("Server:", 1)[1].strip()
        except Exception:
            pass

    # 2. If no "Server:" header but looks like HTTP, just grab the status line
    if "HTTP/" in banner:
        return banner.splitlines()[0]

    # 3. If it's something else (SSH, FTP), just return it as-is
    return banner


def update_vuln_db():
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    print(f"{GREY}[*] Fetching Exploit Database from {url}{RESET}")

    try:
        # 1. Fetches the csv file
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as res:
            data = res.read().decode("utf-8")

        # 2. Parse the CSV
        # This makes the string (data) act like a file, allowing csv.reader to parse it directly.
        csv_reader = csv.reader(io.StringIO(data))
        next(csv_reader)  # Skips the header row

        exploits = []
        # id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
        for row in csv_reader:
            # Filter for Remote/Web exploits to keep it relevant
            # if len(row) > 11 and ("remote" in row[5] or "webapp" in row[5] or "dos" in row[5]):
            if len(row) > 11 and ("remote" in row[5] or "webapp" in row[5]):
                exploits.append({
                    "id": row[0],
                    "file": row[1],
                    "description": row[2],
                    "verified": row[10] if len(row) > 10 else "",
                    "CVE": row[11] if len(row) > 11 else "",
                })

        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(exploits, f)

        print(f"{GREY}[{GREEN}+{GREY}] Database updated! Loaded {len(exploits)} remote exploits.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error! Update failed: {e}{RESET}")


def load_vuln_db():
    if not os.path.exists(DB_PATH):
        return []
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"{RED}[!] Error loading exploit database: {e}{RESET}")
        return []


def version_compare(banner_ver, exploit_ver, operator):
    try:
        # Normalize "2.4" -> [2, 4, 0]
        v1 = [int(x) for x in banner_ver.split('.') if x.isdigit()]
        v2 = [int(x) for x in exploit_ver.split('.') if x.isdigit()]

        # Pad to ensure equal length for comparison
        while len(v1) < len(v2): v1.append(0)
        while len(v2) < len(v1): v2.append(0)

        # Perform Comparison
        if operator == '<': return v1 < v2
        if operator == '>': return v1 > v2
        if operator == '<=': return v1 <= v2
        if operator == '>=': return v1 >= v2
        if operator == '==': return v1 == v2
        return False
    except Exception:
        return False


def check_vulnerabilities(banner, db) -> list:
    if not banner or not db: return []

    # 1. Clean & Tokenize
    # Remove text in parentheses (e.g., "(Ubuntu)")
    clean_banner = re.sub(r'\(.*?\)', '', banner).lower()
    # Replace non-alphanumeric chars with spaces
    clean_banner = re.sub(r'[^\w\.]', ' ', clean_banner)

    banner_tokens = [t for t in clean_banner.split() if len(t) > 1 and not t[0].isdigit()]

    # 2. Extract Version
    banner_version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', clean_banner)
    banner_version = banner_version_match.group(1) if banner_version_match else None

    if not any(char.isdigit() for char in clean_banner): return []

    hits = []

    for exploit in db:
        desc = exploit['description'].lower()

        # PHASE A: Product Name Match
        # If banner has tokens (like "apache"), ensuring ALL of them are in the desc
        text_tokens = [t for t in banner_tokens if not t[0].isdigit()]

        # If we have text tokens (e.g. "apache"), we require at least ONE to match.
        # This fixes the issue where "Apache (Ubuntu)" fails because "Ubuntu" isn't in the description.
        if text_tokens:
            if not any(token in desc for token in text_tokens):
                continue

        # PHASE B: Version Math (Priority)
        match_found_via_math = False
        if banner_version:
            # Split the description by '/' or ',' which ExploitDB often uses for 'OR' (different version branches)
            # This prevents the AND logic from failing on "Apache < 2.2.34 / < 2.4.27"
            for part in re.split(r'\s*/\s*|\s*,\s*', desc):
                part_match = False
                
                # 1. Hyphenated Ranges (e.g., 1.2.0 - 1.5.0)
                for hyphen_match in re.finditer(r'(\d+\.\d+(?:\.\d+)?)\s*-\s*(\d+\.\d+(?:\.\d+)?)', part):
                    start_ver = hyphen_match.group(1)
                    end_ver = hyphen_match.group(2)
                    if version_compare(banner_version, start_ver, '>=') and version_compare(banner_version, end_ver, '<='):
                        part_match = True
                        break
                
                if part_match:
                    hits.append(exploit)
                    match_found_via_math = True
                    break
                    
                # 2. Relational Operators (e.g., >= 1.2.0 < 1.5.0)
                constraints = list(re.finditer(r'(?<!\S)([<>]=?)\s*(\d+\.\d+(?:\.\d+)?)', part))
                if constraints:
                    # AND evaluation: all constraints in this part must be true
                    all_match = True
                    for math_match in constraints:
                        operator = math_match.group(1)
                        exploit_ver = math_match.group(2)
                        if not version_compare(banner_version, exploit_ver, operator):
                            all_match = False
                            break
                            
                    if all_match:
                        hits.append(exploit)
                        match_found_via_math = True
                        break

            if match_found_via_math:
                continue

        # PHASE C: Exact String Match (Fallback)
        # Only check this if Math didn't already trigger a hit
        if not match_found_via_math and banner_version and banner_version in desc:
            hits.append(exploit)

    # Deduplicate and return
    unique_hits = {v['id']: v for v in hits}.values()
    return list(unique_hits)

# Scan port
def scan_port(ip: str, port: int, timeout: float = 1.0) -> tuple[int, str] | None:
    try:
        # Create Socket(IPv4, TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout

        # Handle SSL Wrapping for HTTPS
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                s = context.wrap_socket(s, server_hostname=ip)
            except Exception:
                pass

        result = s.connect_ex((ip, port))  # Tries to connect to the port: returns 0 if successful, otherwise returns 1

        if result == 0:
            banner = None

            shy_ports = [80, 443, 8080, 8443]

            # STEALTH PROBE: Looks like a real browser (Firefox/Chrome)
            probe = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            # 1. Check known Shy Ports (Speak First!)
            if port in shy_ports:
                try:
                    s.send(probe)
                    banner = s.recv(4096).decode(errors='ignore').strip()
                except Exception:
                    pass

            # 2. The Passive Listen (SSH/FTP)
            if not banner:
                try:
                    banner = s.recv(4096).decode(errors='ignore').strip()
                except Exception:
                    pass

            # 3. The Active Poke (Safety Net)
            if not banner:
                try:
                    s.send(probe)
                    banner = s.recv(4096).decode(errors='ignore').strip()
                except Exception:
                    pass

            s.close()

            # Clean up the banner if we found one
            if banner:
                banner = parse_banner(banner)

            # OS Lookup (Fallback)
            if not banner:
                try:
                    # Ask the Operating System "What is port 80 usually?"
                    banner = socket.getservbyport(port, "tcp")
                except OSError:
                    # If the OS doesn't know, finally give up
                    banner = "Unknown Service"

            return (port, banner)

        s.close()
        return None
    except Exception:
        return None


def main():
    print_banner_art()
    args = get_args()

    if args.update or not os.path.exists(DB_PATH):
        if not os.path.exists(DB_PATH):
            print(f"[{YELLOW}!{RESET}] Vulnerability Database missing. Initializing auto-download...")
        update_vuln_db()

    print(f"{GREY}[*] Loading Vulnerability Database...{RESET}", end=" ")
    vuln_db = load_vuln_db()
    print(f"Success! Loaded {len(vuln_db)} exploits.")

    target = args.target
    ports = parse_ports(args.ports)
    # Get configuration based on speed argument
    max_threads, timeout_setting = get_scan_config(args.speed)

    # Simple sanitization to remove http:// or https://
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    # Removes trailing /
    if target.endswith("/"):
        target = target[:-1]

    if args.ports == "-":
        print(f"{GREY}[*] Scanning ALL ports (1-65535).{RESET}")
    elif args.ports is None:
        print(f"{GREY}[*] No ports specified. Scanning Nmap's statistical Top 1000 ports.{RESET}")
    elif isinstance(ports, range):
        print(f"{GREY}[*] Scanning custom range: ({ports.start}-{ports.stop - 1}){RESET}")
    else:
        print(f"{GREY}[*] Target ports: {', '.join(map(str, ports))}{RESET}")

    print(f"{GREY}[*] Target: {target}{RESET}")
    print(f"{GREY}[*] Speed Level: {args.speed} ({max_threads} threads, {timeout_setting}s timeout){RESET}")
    print(f"{GREY}[*] Total ports to scan: {len(ports)}{RESET}")
    print(f"\n{BOLD}==== LIVE SCAN RESULTS ===={RESET}")

    open_ports = []
    start_time = time.time()
    scanned_count = 0
    total_ports = len(ports)

    # Initialize Executor MANUALLY (No 'with' keyword allows for instant Ctrl+C exit)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

    try:
        # This creates a dictionary: {FutureObject: PortNumber, ...}
        future_to_port = {
            executor.submit(scan_port, target, port, timeout_setting): port  # type: ignore
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result()  # This is the return value from scan_port
            except Exception:
                result = None

            if result:
                port_number, banner_text = result
                vulns = check_vulnerabilities(banner_text, vuln_db)
                open_ports.append((port_number, banner_text, vulns))

                # Wipe line (100 spaces), Print Open Port, Wipe again
                sys.stdout.write("\r" + " " * 100 + "\r")

                raw_text = str(banner_text or "")
                clean_text = "".join(c if c.isprintable() else " " for c in raw_text)
                clean_text = " ".join(clean_text.split())
                
                short_banner = clean_text[:40].ljust(45)  # type: ignore
                if vulns:
                    print(
                        f" {GREY}[*]{RESET} Port {port_number:<5} {GREEN}OPEN{RESET}   {CYAN}{short_banner}{RESET} {RED}[VULNERABLE]{RESET}")
                else:
                    print(
                        f" {GREY}[*]{RESET} Port {port_number:<5} {GREEN}OPEN{RESET}   {CYAN}{short_banner}{RESET} {GREEN}[SAFE]{RESET}")

            scanned_count += 1
            current_time = time.time()
            elapsed_time = current_time - start_time

            # Avoid divide by 0 error
            if elapsed_time > 0:
                scan_speed = scanned_count / elapsed_time
            else:
                scan_speed = 0

            # Draw progress bar
            percent = (scanned_count / total_ports) * 100
            bar_length = 30
            filled_length = int(bar_length * scanned_count // total_ports)
            bar = '=' * filled_length + '-' * (bar_length - filled_length)

            sys.stdout.write(
                f"\r {GREY}[{bar}] {percent:.1f}% | {scanned_count}/{total_ports} | {scan_speed:.2f} ports/s{RESET}")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scanning stopped! User interrupted.{RESET}")
        os._exit(1)  # Nuclear option for instant exit
    finally:
        executor.shutdown(wait=True)

    report_lines: list[str] = []
    
    report_lines.append(f"\n\n{BOLD}==== DETAILED SCAN REPORT ===={RESET}")
    report_lines.append(f"{GREY}[*] Scan Completed in {time.time() - start_time:.2f} seconds.{RESET}")

    if open_ports:
        # Sort by the first item in tuple (the port number)
        open_ports.sort(key=lambda x: x[0])
        report_lines.append(f"{GREY}[*] Open Ports Found: {len(open_ports)}{RESET}")

        for port, banner, vulns in open_ports:
            # Clean up newlines in banners for display
            clean_banner = banner.replace('\n', ' ').replace('\r', '')
            report_lines.append(f"\n{GREY}" + "-" * 60 + f"{RESET}")
            report_lines.append(f"{BOLD}PORT {port:<5} | {CYAN}{clean_banner}{RESET}")

            if vulns:
                vulns_list: list[dict] = list(vulns)
                count = len(vulns_list)
                max_items = len(vulns_list)  # Change how many items to print out
                vulns_list.sort(key=lambda x: x.get('verified', '0'), reverse=True)

                report_lines.append(f"{RED}    [!] DETECTED {count} POTENTIAL EXPLOITS:{RESET}")

                for i in range(min(count, max_items)):
                    v = vulns_list[i]
                    is_last_exploit = (i == min(count, max_items) - 1)
                    branch = "└──" if is_last_exploit else "├──"
                    wall = "    " if is_last_exploit else "│   "

                    header_info = f"EDB-ID: {BOLD}{v['id']}{RESET}"
                    if v.get('CVE'):
                        header_info += f" | {YELLOW}{v.get('CVE')}{RESET}"
                    if v.get('verified') == "1":
                        header_info += f" {GREEN}[✔ Verified]{RESET}"

                    report_lines.append(f"{GREY}    {branch}{RESET} {header_info}")
                    title = v.get('description', 'Unknown').strip()
                    report_lines.append(f"{GREY}    {wall}├──{RESET} Title: {title}")

                    exploit_url = f"https://www.exploit-db.com/exploits/{v['id']}"
                    report_lines.append(f"{GREY}    {wall}├──{RESET} View:  {BLUE}{exploit_url}{RESET}")

                    raw_url = f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/{v['file']}"
                    report_lines.append(f"{GREY}    {wall}└──{RESET} Raw Code:  {raw_url}")
                # if count > max_items:
                #     report_lines.append(f"{GREY}    └── ... and {count - max_items} more exploits hidden.{RESET}")
            else:
                report_lines.append(f"    {GREEN}[+] No known exploits found.{RESET}")
    else:
        report_lines.append(f"{RED}[-] No open ports found.{RESET}")

    # Print to console
    for line in report_lines:
        print(line)
        
    # Write to file if -o flag is present
    if args.output:
        try:
            # Strip ANSI color codes before writing to file
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            with open(args.output, "w", encoding="utf-8") as f:
                for line in report_lines:
                    clean_line = ansi_escape.sub('', line)
                    f.write(clean_line + "\n")
            print(f"\n{GREEN}[+] Report saved to {args.output}{RESET}")
        except Exception as e:
            print(f"\n{RED}[!] Failed to save report to {args.output}: {e}{RESET}")


if __name__ == "__main__":
    main()