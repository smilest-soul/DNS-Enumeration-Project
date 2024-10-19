# DNS Enumeration Project

This project focuses on DNS Enumeration and Vulnerability Analysis using `DNSRecon`. It automates the process of retrieving DNS records and identifying potential vulnerabilities in domain configurations. This tool is designed for cybersecurity professionals and network administrators who want to strengthen their network security by analyzing DNS setups.

## Features

- **Enumerates DNS Records**: A, MX, NS, SOA, CNAME, TXT, and other DNS record types.
- **Performs Reverse DNS Lookups**: Maps IP addresses back to domain names to detect possible misconfigurations.
- **Identifies Zone Transfers**: Detects DNS zone transfers, which can expose sensitive domain information.
- **Scans for DNSSEC Support**: Identifies if the target domain supports DNSSEC (Domain Name System Security Extensions).
- **Subdomain Enumeration**: Finds subdomains linked to the target domain to assess exposure.
- **Generates Reports**: Creates PDF reports for easy sharing and future reference.
- **Vulnerability Detection**: Identifies potential security weaknesses in DNS configurations.

---

## Motivation

DNS vulnerabilities are a prime target for attackers, and misconfigurations can expose sensitive information or lead to service disruptions. This project aims to simplify the DNS enumeration process, automate vulnerability analysis, and provide clear, actionable reports to improve domain security.

---

## Prerequisites

Ensure that you have the following installed on your system:

- **Python 3.x**: This project is developed using Python.
- **Required Python modules**: The project depends on external modules such as `dnsrecon` and `fpdf2`. Install them using the command below:
  ```bash
  pip install dnsrecon fpdf2


Installation
Follow the steps below to set up the project on your local machine:

Clone the Repository:

bash
Copy code
git clone https://github.com/smilest-soul/DNS-Enumeration-Project.git
cd DNS-Enumeration-Project
Install Dependencies: Use pip to install all required dependencies from the requirements.txt file:

bash
Copy code
pip install -r requirements.txt
Check DNSRecon Installation: Verify if dnsrecon is installed and working by running:

bash
Copy code
dnsrecon -h

