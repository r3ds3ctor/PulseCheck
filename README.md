# PulseCheck 🔍  
### Advanced System Vulnerability Scanner  

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)  
![License](https://img.shields.io/badge/License-MIT-green)  
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/r3ds3ctor/PulseCheck/pulls)  

PulseCheck is a **Python-based vulnerability scanner** that audits system packages, kernel versions, and configurations against known CVEs. It generates detailed HTML/text reports for security assessments.  

---

## Features ✨  
✅ **Comprehensive System Analysis**  
- Detects OS, kernel, and critical package versions (Bash, OpenSSL, Python, etc.).  
- Supports **Linux** and **macOS**.  

✅ **CVE Database Integration**  
- Queries the **NVD API** for real-time vulnerability data.  
- Version-specific checks with severity ratings (Critical/High/Medium).  

✅ **Professional Reporting**  
- **HTML report** with interactive Bootstrap styling.  
- **Text report** with PrettyTable formatting.  

✅ **Progress Tracking**  
- tqdm-powered progress bars for scan transparency.  

✅ **Security-First**  
- Minimal dependencies, no root required (but recommended for full scans).  

---

## Installation 🛠️  

### Prerequisites  
- Python 3.8+  
- `pip` package manager  

### Steps  
1. Clone the repository:  
   ```bash
   git clone https://github.com/r3ds3ctor/PulseCheck.git
   cd PulseCheck
   pip install -r requirements.txt
   python3 PulseCheck.py
   ```
   (Optional) For NVD API rate limit bypass (50+ requests/day):

    Get a free API key from NVD API Portal.

    Set it in the script via self.api_key.

## HTML Preview
```
=== VULNERABILITY ASSESSMENT REPORT ===
Date: 2025-06-02 14:30:00
System Type: Linux
Distribution: Ubuntu 22.04 LTS
Kernel Version: 5.15.0-76-generic

Critical Packages:
- bash: 5.1-6ubuntu1
- openssl: 3.0.2-0ubuntu1.10

VULNERABILITIES FOUND:
+---------------------+------------+-------------+-------------------------------------+
| Title              | Criticality| CVE         | Description                         |
+---------------------+------------+-------------+-------------------------------------+
| Dirty Pipe         | High       | CVE-2022-0847| Linux kernel privilege escalation...|
+---------------------+------------+-------------+-------------------------------------+

```

## Author
Alexander B

## 🤝 Contributing
This project thrives on community contributions. If you'd like to suggest improvements, report issues, or add new features, feel free to open a pull request.  
If you’d like to support future development, you can do so here: 

☕ [buymeacoffee.com/alexboteroh]
