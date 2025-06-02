#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import platform
import os
import re
import requests
import time
from datetime import datetime
from prettytable import PrettyTable
import json
import sys
from packaging import version
from tqdm import tqdm
import html

class PulseCheck:
    def __init__(self):
        self.system_info = {}
        self.results = []
        self.api_key = None  # Set your NVD API key here
        self.api_delay = 6  # NVD API rate limit (requests per second)
        self.is_macos = False
        self.is_linux = False
        self.verbose = False
        self.progress = None  # Progress bar handler

    def update_progress(self, description, current=0, total=1):
        """Update progress bar with current task"""
        if self.progress is None:
            self.progress = tqdm(total=total, desc=description, unit="step")
        else:
            self.progress.set_description(description)
            self.progress.total = total
            self.progress.n = current
            self.progress.refresh()

    def close_progress(self):
        """Close progress bar if active"""
        if self.progress is not None:
            self.progress.close()
            self.progress = None

    def get_system_info(self):
        """Collect system information (OS, kernel, packages)"""
        self.update_progress("Gathering system information")
        
        info = {
            'os_type': 'Linux' if sys.platform == 'linux' else 'macOS' if sys.platform == 'darwin' else 'Unknown',
            'kernel': platform.release(),
            'distribution': 'Unknown',
            'packages': {},
            'package_versions': {},
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        self.is_macos = info['os_type'] == 'macOS'
        self.is_linux = info['os_type'] == 'Linux'

        # Get distribution info
        if self.is_linux:
            try:
                with open('/etc/os-release') as f:
                    for line in f:
                        if 'PRETTY_NAME' in line:
                            info['distribution'] = line.split('=')[1].strip().strip('"')
                            break
            except:
                pass
        elif self.is_macos:
            info['distribution'] = f"macOS {platform.mac_ver()[0]}"

        # Check critical packages
        critical_packages = {
            'bash': ['bash', '--version'],
            'openssl': ['openssl', 'version'],
            'sudo': ['sudo', '--version'],
            'ssh': ['ssh', '-V'],
            'python': ['python', '--version']
        }
        
        self.update_progress("Checking packages", 0, len(critical_packages))
        
        for i, (pkg, cmd) in enumerate(critical_packages.items()):
            try:
                version_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()
                info['packages'][pkg] = version_output
                
                version_match = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)', version_output)
                if version_match:
                    info['package_versions'][pkg] = version_match.group(0)
                else:
                    info['package_versions'][pkg] = "unknown"
                    
            except Exception as e:
                info['packages'][pkg] = f"Not found ({str(e)})"
                info['package_versions'][pkg] = "unknown"
            
            self.update_progress("Checking packages", i+1)

        return info

    def compare_versions(self, v1, v2):
        """Compare version strings using packaging library"""
        try:
            return version.parse(v1) >= version.parse(v2)
        except:
            return v1 >= v2

    def check_kernel_vulnerabilities(self):
        """Check for known kernel vulnerabilities"""
        if not self.is_linux:
            return

        known_vulns = [
            {
                "title": "Dirty Pipe",
                "cve": "CVE-2022-0847",
                "min_version": "5.8",
                "max_version": "5.16.11",
                "severity": "High",
                "description": "Linux kernel privilege escalation via pipe subsystem."
            },
            {
                "title": "PwnKit",
                "cve": "CVE-2021-4034",
                "severity": "High",
                "description": "pkexec local privilege escalation in polkit."
            }
        ]

        self.update_progress("Checking kernel vulnerabilities", 0, len(known_vulns))
        
        for i, vuln in enumerate(known_vulns):
            if 'min_version' in vuln and 'max_version' in vuln:
                if (self.compare_versions(self.system_info['kernel'], vuln['min_version']) and 
                   not self.compare_versions(self.system_info['kernel'], vuln['max_version'])):
                    self.add_vulnerability(
                        vuln['title'],
                        vuln['cve'],
                        vuln['severity'],
                        vuln['description'],
                        "Update kernel to patched version."
                    )

            if vuln['title'] == "PwnKit" and os.path.exists("/usr/bin/pkexec"):
                self.add_vulnerability(
                    vuln['title'],
                    vuln['cve'],
                    vuln['severity'],
                    vuln['description'],
                    "Update polkit package."
                )
            
            self.update_progress("Checking kernel vulnerabilities", i+1)

    def check_cve_with_nvd_api(self, software_name, version=None, exact_match=False):
        """Query NVD API for CVEs"""
        findings = []
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        search_term = f"{software_name}"
        if version and exact_match:
            search_term += f" {version}"
        
        params = {
            "keywordSearch": search_term,
            "resultsPerPage": 50,
            "isExactMatch": str(exact_match).lower()
        }

        headers = {
            "User-Agent": "PulseCheck/2.0",
            "Accept": "application/json"
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            if self.verbose:
                print(f"[*] Querying NVD for: {search_term} (exact: {exact_match})")
                
            response = requests.get(base_url, params=params, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()

            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                
                # Skip duplicates
                if any(r['CVE'] == cve_id for r in self.results):
                    continue
                
                description = next((desc["value"] for desc in cve["descriptions"] 
                                 if desc["lang"] == "en"), "No description available")
                
                # Extract severity
                severity = "Unknown"
                cvss_metrics = cve.get("metrics", {})
                
                if "cvssMetricV31" in cvss_metrics:
                    severity = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in cvss_metrics:
                    severity = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in cvss_metrics:
                    severity = cvss_metrics["cvssMetricV2"][0]["baseSeverity"]
                
                # Check affected versions
                affected_versions = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if "versionStartIncluding" in match or "versionEndIncluding" in match:
                                version_info = {
                                    "software": match.get("criteria", "").split(":")[4],
                                    "start": match.get("versionStartIncluding"),
                                    "end": match.get("versionEndIncluding")
                                }
                                affected_versions.append(version_info)
                
                is_affected = False
                mitigation = "Unknown"
                
                if version and affected_versions:
                    for ver_info in affected_versions:
                        if ver_info["software"] != software_name:
                            continue
                            
                        if (not ver_info["start"] or self.compare_versions(version, ver_info["start"])) and 
                           (not ver_info["end"] or not self.compare_versions(version, ver_info["end"])):
                            is_affected = True
                            mitigation = f"Affected versions: {ver_info['start'] or 'any'} to {ver_info['end'] or 'any'}"
                            break
                elif not version:
                    is_affected = True
                    mitigation = "General advisory - verify version applicability"
                
                if is_affected:
                    findings.append({
                        "title": f"{cve_id} - {software_name}",
                        "cve": cve_id,
                        "criticality": severity,
                        "description": description,
                        "mitigation": mitigation
                    })

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[!] NVD API error: {e}")
        except Exception as e:
            if self.verbose:
                print(f"[!] NVD processing error: {e}")

        return findings

    def check_system_with_nvd(self):
        """Check all system components against NVD"""
        self.update_progress("Querying NVD database")
        
        tasks = []
        
        # Kernel check
        if self.is_linux:
            tasks.append(("Linux Kernel", self.system_info['kernel'], True))
        
        # Distribution check
        if "Ubuntu" in self.system_info['distribution']:
            distro_version = self.system_info['distribution'].split()[-1]
            tasks.append(("Ubuntu Linux", distro_version, True))
        elif "Debian" in self.system_info['distribution']:
            distro_version = self.system_info['distribution'].split()[-1]
            tasks.append(("Debian Linux", distro_version, True))
        elif self.is_macos:
            macos_version = self.system_info['distribution'].split()[1]
            tasks.append(("macOS", macos_version, True))
        
        # Package checks
        for pkg, ver in self.system_info['package_versions'].items():
            if ver != "unknown":
                tasks.append((pkg.capitalize(), ver, True))
        
        self.update_progress("Querying NVD", 0, len(tasks))
        
        for i, (name, ver, exact) in enumerate(tasks):
            cves = self.check_cve_with_nvd_api(name, ver, exact)
            for cve in cves:
                self.add_vulnerability(cve["title"], cve["cve"], cve["criticality"], 
                                     cve["description"], cve["mitigation"])
            
            self.update_progress("Querying NVD", i+1)
            time.sleep(self.api_delay)

    def add_vulnerability(self, title, cve, crit, description, mitigation=None):
        """Add validated vulnerability to results"""
        if any(r['CVE'] == cve for r in self.results):
            return
            
        # Skip low-severity issues
        if crit == "Low":
            return
            
        self.results.append({
            "Title": title,
            "CVE": cve,
            "Criticality": crit,
            "Description": description,
            "Mitigation": mitigation or "Consult vendor advisory"
        })

    def generate_html_report(self, filename):
        """Generate interactive HTML report"""
        severity_colors = {
            "Critical": "danger",
            "High": "warning",
            "Medium": "info",
            "Low": "secondary"
        }
        
        # Sort by severity
        self.results.sort(key=lambda x: ["Critical", "High", "Medium", "Low"].index(x['Criticality']))
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PulseCheck Vulnerability Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .vuln-card {{ transition: all 0.3s ease; }}
        .vuln-card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }}
        .badge-severity {{ font-size: 0.9rem; padding: 0.5em 0.75em; }}
        .cve-link {{ color: inherit; text-decoration: none; }}
        .cve-link:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container py-5">
        <div class="text-center mb-5">
            <h1 class="display-4 fw-bold text-primary">PulseCheck Vulnerability Report</h1>
            <p class="lead text-muted">Generated on {self.system_info['scan_date']}</p>
        </div>
        
        <!-- System Info Section -->
        <div class="row mb-5">
            <div class="col-md-6">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">System Information</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span>System Type</span>
                                <span class="fw-bold">{self.system_info['os_type']}</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span>Distribution</span>
                                <span class="fw-bold">{html.escape(self.system_info['distribution'])}</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span>Kernel Version</span>
                                <span class="fw-bold">{html.escape(self.system_info['kernel'])}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Packages Section -->
            <div class="col-md-6">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">Package Versions</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
        """
        
        for pkg, ver in self.system_info['packages'].items():
            html_content += f"""
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span>{pkg.capitalize()}</span>
                                <span class="fw-bold">{html.escape(ver)}</span>
                            </li>
            """
        
        html_content += """
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Section -->
        <div class="mb-4">
            <h2 class="h4 fw-bold">
                <span class="badge bg-primary rounded-pill me-2">{len(self.results)}</span>
                Detected Vulnerabilities
            </h2>
            <div class="progress mt-2" style="height: 8px;">
                <div class="progress-bar bg-danger" style="width: {len([r for r in self.results if r['Criticality'] == 'Critical'])/len(self.results)*100 if self.results else 0}%"></div>
                <div class="progress-bar bg-warning" style="width: {len([r for r in self.results if r['Criticality'] == 'High'])/len(self.results)*100 if self.results else 0}%"></div>
                <div class="progress-bar bg-info" style="width: {len([r for r in self.results if r['Criticality'] == 'Medium'])/len(self.results)*100 if self.results else 0}%"></div>
            </div>
        </div>
        """
        
        for vuln in self.results:
            color = severity_colors.get(vuln['Criticality'], 'secondary')
            
            html_content += f"""
        <div class="card mb-3 vuln-card border-{color}">
            <div class="card-header d-flex justify-content-between align-items-center bg-{color} bg-opacity-10">
                <h5 class="mb-0">
                    <a href="https://nvd.nist.gov/vuln/detail/{vuln['CVE']}" target="_blank" class="cve-link">
                        {html.escape(vuln['Title'])}
                    </a>
                </h5>
                <span class="badge badge-severity bg-{color}">{vuln['Criticality']}</span>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <p class="card-text">{html.escape(vuln['Description'])}</p>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-light">
                            <div class="card-body">
                                <h6 class="card-subtitle mb-2 text-muted">Remediation</h6>
                                <p class="card-text">{html.escape(vuln['Mitigation'])}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card-footer bg-transparent">
                <small class="text-muted">CVE: <a href="https://nvd.nist.gov/vuln/detail/{vuln['CVE']}" target="_blank">{vuln['CVE']}</a></small>
            </div>
        </div>
            """
        
        html_content += """
        <footer class="mt-5 text-center text-muted">
            <p>Report generated by PulseCheck</p>
        </footer>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)

    def generate_text_report(self, filename):
        """Generate formatted text report"""
        self.results.sort(key=lambda x: ["Critical", "High", "Medium", "Low"].index(x['Criticality']))
        
        table = PrettyTable()
        table.field_names = ["Title", "Criticality", "CVE", "Description", "Mitigation"]
        table.align = "l"
        table.max_width = 40
        
        for res in self.results:
            table.add_row([
                res["Title"],
                res["Criticality"],
                res["CVE"],
                res["Description"][:100] + "..." if len(res["Description"]) > 100 else res["Description"],
                res["Mitigation"][:100] + "..." if len(res["Mitigation"]) > 100 else res["Mitigation"]
            ])

        report_content = f"""
=== PULSECHECK VULNERABILITY REPORT ===
Date: {self.system_info['scan_date']}
System Type: {self.system_info['os_type']}
Distribution: {self.system_info['distribution']}
Kernel Version: {self.system_info['kernel']}

Critical Packages:
"""
        for pkg, ver in self.system_info['packages'].items():
            report_content += f"- {pkg}: {ver}\n"

        report_content += f"""
VULNERABILITIES FOUND:
{table}
"""
        with open(filename, 'w') as f:
            f.write(report_content)

    def generate_report(self):
        """Generate both report formats"""
        self.update_progress("Generating reports")
        
        base_filename = f"pulsecheck_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # HTML report
        html_filename = f"{base_filename}.html"
        self.generate_html_report(html_filename)
        
        # Text report
        text_filename = f"{base_filename}.txt"
        self.generate_text_report(text_filename)
        
        print(f"\n[+] HTML report saved to: {html_filename}")
        print(f"[+] Text report saved to: {text_filename}")

    def run(self):
        """Execute full vulnerability scan"""
        try:
            print("=== PULSECHECK VULNERABILITY SCAN ===")
            
            # Collect system data
            self.system_info = self.get_system_info()
            
            print(f"Detected system: {self.system_info['distribution']} ({self.system_info['os_type']})")
            print(f"Kernel version: {self.system_info['kernel']}")
            
            # Run checks
            self.check_kernel_vulnerabilities()
            self.check_system_with_nvd()
            self.generate_report()
            
        finally:
            self.close_progress()

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print("[!] Warning: Some checks require root privileges for complete results.")
        
        scanner = PulseCheck()
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        exit(1)