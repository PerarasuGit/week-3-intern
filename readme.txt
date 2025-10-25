🧠 Port Scanner – Week 3 Internship Project

This week’s task focuses on simulating a Network Port Scanner using Python.
The goal is to identify open network ports on target IP addresses and generate a basic vulnerability report.

🔍 Overview

A port scanner is a cybersecurity tool used to detect open communication endpoints (ports) on devices connected to a network.
Attackers often use port scanning to find weak points — but cybersecurity professionals use it ethically for vulnerability assessment and network security testing.

This project demonstrates how a basic scanner works internally.

⚙️ Features

Scans multiple IP addresses for common ports: 21, 22, 80, 443, 3306

Identifies services like FTP, SSH, HTTP, HTTPS, MySQL

Adds a risk note with every open port

Generates a CSV report with columns:

IP Address

Port

Service

Status

Risk Note

Handles timeouts and connection errors safely

Clean, readable code with comments

🧩 How It Works

The user defines a list of target IPs in the script.

For each IP, the program attempts to connect to a list of common ports.

If a port is open, it records:

Port number

Service type (e.g., SSH, HTTP)

A short risk note

Results are stored in vulnerability_report.csv for easy viewing.

Uses Python’s socket and threading modules for performance.

💻 Usage

Open the file port-scanner.py in your Python editor (like VS Code or IDLE).

Edit the list:

target_ips = ["127.0.0.1", "192.168.1.1", "192.168.1.10"]


Run the script:

python port-scanner.py


Wait for the scan to finish — results will be saved as vulnerability_report.csv.

🧾 Sample Output
Starting scan of 3 target(s): ['127.0.0.1', '192.168.1.1', '192.168.1.10']
Scanning 127.0.0.1...
Scanning 192.168.1.1...
Scanning 192.168.1.10...
Scan complete! Results saved to vulnerability_report.csv
Time taken: 0:00:03.214


Sample CSV content:

IP Address	Port	Service	Status	Risk Note
127.0.0.1	22	SSH	OPEN	Secure shell – check login policy
127.0.0.1	80	HTTP	OPEN	Web port – ensure HTTPS redirect
192.168.1.1	3306	MySQL	CLOSED	Not accessible – safe
⚠️ Ethical Note

This tool is for educational and ethical use only.
Scanning systems without permission is illegal under cybersecurity laws.
Use this scanner only in controlled lab environments or on your own networks.

📦 Files Included

port-scanner.py → main Python script

vulnerability_report.csv → output report

WEEK3_detailed_report.txt → this explanation file

🏁 Skills Learned

✅ Basics of network scanning
✅ Socket programming in Python
✅ Understanding open ports and risk levels
✅ Writing structured reports
✅ Safe and responsible cybersecurity practices