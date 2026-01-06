Install Python Pages
 
Advanced Subdomain and Origin IP Discovery Tool with WAF Bypass

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Target domain to scan
  -o, --output OUTPUT   Output file to save results
  -t, --threads THREADS
                        Number of threads for brute force
  -v, --verbose         Verbose output

🚀 Features
Multi-Source Subdomain Discovery: Uses passive and active techniques

WAF Detection & Bypass: Identifies and bypasses common WAF solutions

Origin IP Discovery: Finds real backend IPs behind CDNs

Smart Brute Forcing: Advanced pattern-based subdomain enumeration

Port Scanning: Identifies open ports on discovered hosts

Threaded Execution: High-performance parallel processing

Multiple Output Formats: JSON, CSV, TXT, and HTML reports

Cloud Integration: Supports AWS, Azure, and GCP reconnaissance
📦 Installation
Quick Install
bash
git clone https://github.com/githubisrar/Orign-ip-Finder.git
cd Orign-ip-Finder
	python3 Orign-ip-Finder.py -d example.com
