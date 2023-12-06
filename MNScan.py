import subprocess
import argparse
import re
import json
from collections import defaultdict
import concurrent.futures

def is_valid_ip(ip):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return bool(ip_pattern.match(ip))


def parse_masscan_output(masscan_output):
    try:
        results = json.loads(masscan_output)
    except json.JSONDecodeError as e:
        print(f"Error decoding Masscan output: {e}")
        print("Problematic content:", masscan_output)
        return None

    ip_ports_mapping = defaultdict(list)

    for result in results:
        ip = result.get("ip", "")
        ports = result.get("ports", [])

        ip_ports_mapping[ip].extend([str(port_info["port"]) for port_info in ports])

    return ip_ports_mapping

def nmap_scan(ip, ports, output_file_path):
    nmap_path = "/opt/homebrew/bin/nmap"
    ports_str = ",".join(ports)
    nmap_cmd = ["nmap", ip, "-p", ports_str, "-sV", "-Pn", "-oN", output_file_path, "--append-output"]
    subprocess.run(nmap_cmd, check=True)

    with open(output_file_path, 'r') as f:
        nmap_output = f.read()

    pattern = rf'Nmap scan report for {re.escape(ip)}([\s\S]*?)Nmap done at'
    matches = re.findall(pattern, nmap_output)

    for match in matches:
        https_ports = re.findall(r'(\d+)/tcp\s+open\s+.*ssl.*\n', match)
        http_ports = re.findall(r'(\d+)/tcp\s+open\s+http', match)

    if https_ports:
        with open(output_file_path, 'a') as f:
            print(f"\nHTTPS Services:")
            f.write("\n\nHTTPS Services:\n")
            for port in https_ports:
                print(f"\033[92mhttps://{ip}:{port}\033[0m")
                f.write(f"https://{ip}:{port}\n")

    if http_ports:
        with open(output_file_path, 'a') as f:
            print(f"\nHTTP Services:")
            f.write("\n\nHTTP Services:\n")
            for port in http_ports:
                print(f"\033[92mhttp://{ip}:{port}\033[0m")
                f.write(f"http://{ip}:{port}\n")

def run_masscan(output_file_path, target, ports, rate):
    masscan_path = "/usr/local/bin/masscan"
    masscan_output = ""  # Initialize masscan_output here

    if is_valid_ip(target):
        masscan_cmd = ["masscan", target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]
    else:
        masscan_cmd = ["masscan", "-iL", target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]

    try:
        subprocess.run(masscan_cmd, check=True)
        print("Masscan completed successfully.")

        with open(output_file_path, 'r') as f:
            masscan_output = f.read()
            masscan_output = re.sub(r',(?=\s*[\]}])', '', masscan_output)

    except subprocess.CalledProcessError as e:
        print(f"Error running Masscan: {e}")

    if not masscan_output.strip():
        print("Masscan scan result is empty.")
        exit(1)
    
    try:
        ip_ports_mapping = parse_masscan_output(masscan_output)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(nmap_scan, ip, ports, output_file_path) for ip, ports in ip_ports_mapping.items()]
            concurrent.futures.wait(futures)

    except subprocess.CalledProcessError as e:
        print(f"Error running Masscan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Masscan with custom parameters")
    parser.add_argument("-i", "--ip", dest="target", help="Single target IP address")
    parser.add_argument("-f", "--file", dest="target", help="File containing target IPs (one per line)")
    parser.add_argument("-o", "--output", dest="output_file_path", default="./output.txt", help="Output file path, default output.txt")
    parser.add_argument("-r", "--rate", dest="rate", default="1000", help="Scan rate, default 1000")
    parser.add_argument("-p", "--ports", dest="ports", default="1-65535", help="Port range (default: 1-65535)")

    args = parser.parse_args()

    if not args.target:
        print("Please specify either -i/--ip or -f/--file for target IPs.")
        exit(1)

    run_masscan(args.output_file_path, args.target, args.ports, args.rate)
