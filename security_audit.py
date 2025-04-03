import os
import subprocess
import json
import argparse
import requests
import threading
from fpdf import FPDF
import re
import socket

# Function to execute a shell command and return output
def run_command(command):
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        return f"Error: {str(e)}"

# Function to extract services and versions from Nmap output
def extract_services(nmap_output):
    services = {}
    for line in nmap_output.split("\n"):
        match = re.search(r"(\d{1,5}/\w+)\s+open\s+(\S+)\s+(.+)", line)
        if match:
            port, service, version = match.groups()
            services[service] = version.strip() if version else "unknown"
    return services

# Function to query NIST NVD API for CVEs
def check_cve(service_name, version):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_name}%20{version}"
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return [item["cve"]["CVE_data_meta"]["ID"] for item in data.get("result", {}).get("CVE_Items", [])]
    except Exception as e:
        return [f"Error fetching CVE data: {str(e)}"]
    return []

# Function to scan with Nmap
def nmap_scan(target):
    command = f"nmap -sV -O {target}"
    return run_command(command)

# Function to scan with Nikto
def nikto_scan(target):
    command = f"nikto -h {target}"
    return run_command(command)

# Function to generate a structured PDF report
def generate_pdf_report(target, nmap_result, nikto_result, cve_results, output_folder):
    target_clean = target.replace(".", "").replace(":", "")
    output_file = os.path.join(output_folder, f"report_{target_clean}.pdf")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Security Report for {target}", ln=True, align="C")

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "1. Nmap Scan Results", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 7, nmap_result)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "2. Nikto Scan Results", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 7, nikto_result)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "3. Vulnerability Analysis (CVE Lookup)", ln=True)
    pdf.set_font("Arial", "", 10)
    
    if cve_results:
        for service, cves in cve_results.items():
            pdf.cell(0, 7, f"Service: {service}", ln=True)
            for cve in cves:
                pdf.cell(0, 7, f" - {cve}", ln=True)
    else:
        pdf.cell(0, 7, "No known CVEs found.", ln=True)

    pdf.output(output_file)
    print(f"Report saved: {output_file}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Web Server Security Assessment Tool")
    parser.add_argument("target", help="Specify the target server (e.g., example.com or IP)")
    parser.add_argument("--output", help="Specify output folder", default=os.getcwd())
    args = parser.parse_args()

    target = args.target
    output_folder = args.output
    os.makedirs(output_folder, exist_ok=True)

    try:
        # Resolve domain to IP if necessary
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        target_ip = target

    print(f"Scanning target: {target_ip}")

    # Run Nmap and Nikto concurrently
    nmap_thread = threading.Thread(target=lambda: globals().update(nmap_result=nmap_scan(target_ip)))
    nikto_thread = threading.Thread(target=lambda: globals().update(nikto_result=nikto_scan(target_ip)))

    nmap_thread.start()
    nikto_thread.start()
    nmap_thread.join()
    nikto_thread.join()

    # Extract services from Nmap output
    services = extract_services(nmap_result)
    cve_results = {service: check_cve(service, version) for service, version in services.items()}

    # Generate PDF report
    generate_pdf_report(target, nmap_result, nikto_result, cve_results, output_folder)

if _name_ == "_main_":
    main()