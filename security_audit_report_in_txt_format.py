import os
import sys
import subprocess
import re

def run_command(command):
    """Runs a shell command and returns full output."""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors='ignore')

def scan_with_nmap(target):
    print(f"[+] Starting Nmap scan on {target}...")
    return run_command(f"nmap -sV -T4 -p- {target}")

def scan_with_nikto(target):
    print(f"[+] Starting Nikto scan on {target}...")
    return run_command(f"nikto -h http://{target}")

def extract_vulnerabilities(nikto_output):
    print("[+] Extracting vulnerabilities from Nikto output...")
    lines = nikto_output.split('\n')
    vulns = [line for line in lines if (
        "OSVDB" in line or 
        "vulnerable" in line.lower() or 
        "uncommon header" in line.lower() or 
        "X-" in line or 
        "CVE-" in line
    )]
    return "\n".join(vulns) if vulns else "No significant vulnerabilities detected."

def extract_cve_ids(output):
    """Find all CVE IDs in the output."""
    print("[+] Looking for CVEs in scan output...")
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)
    return sorted(set(cve_ids))

def generate_report(target, nmap_data, nikto_data, vuln_summary, cve_ids):
    report_filename = f"{target}_report.txt"
    print(f"[+] Writing full report to {report_filename}...")

    with open(report_filename, "w") as report:
        report.write(f"=== Web Server Security Assessment Report for {target} ===\n\n")

        report.write(">>> [Nmap Full Scan Output]\n")
        report.write("=" * 60 + "\n")
        report.write(nmap_data + "\n\n")

        report.write(">>> [Nikto Full Scan Output]\n")
        report.write("=" * 60 + "\n")
        report.write(nikto_data + "\n\n")

        report.write(">>> [Vulnerability Summary from Nikto]\n")
        report.write("=" * 60 + "\n")
        report.write(vuln_summary + "\n\n")

        report.write(">>> [CVE References Found]\n")
        report.write("=" * 60 + "\n")
        if cve_ids:
            for cve in cve_ids:
                report.write(f"{cve}: https://nvd.nist.gov/vuln/detail/{cve}\n")
        else:
            report.write("No CVEs detected.\n")

    print(f"[✓] Report saved as: {report_filename}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 web_server_security_assessment.py <target IP or domain>")
        sys.exit(1)

    target = sys.argv[1]
    nmap_results = scan_with_nmap(target)
    nikto_results = scan_with_nikto(target)
    vuln_summary = extract_vulnerabilities(nikto_results)
    cve_ids = extract_cve_ids(nikto_results)
    generate_report(target, nmap_results, nikto_results, vuln_summary, cve_ids)

if _name_ == "_main_":
    main()
