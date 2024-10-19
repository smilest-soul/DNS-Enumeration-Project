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


## Installation

Follow these steps to install and set up the project on your local machine:

1. **Clone the Repository**:
   First, clone the GitHub repository to your local system:
   ```bash
   git clone https://github.com/smilest-soul/DNS-Enumeration-Project.git
   cd DNS-Enumeration-Project

# Project Dependencies

The following Python modules are required for the project to function correctly. You can install them individually or use a `requirements.txt` file for bulk installation.

### Required Python Modules:

1. **`dns.resolver`** (from `dnspython` library):
   - Used for DNS queries and resolving DNS records.
   - Install using:
     ```bash
     pip install dnspython
     ```

2. **`requests`**:
   - For making HTTP requests (used for querying online APIs).
   - Install using:
     ```bash
     pip install requests
     ```

3. **`flask`**:
   - Web framework to run the application.
   - Install using:
     ```bash
     pip install Flask
     ```

4. **`flask_session`**:
   - For managing sessions in Flask.
   - Install using:
     ```bash
     pip install Flask-Session
     ```

5. **`reportlab`**:
   - Used for generating PDF reports.
   - Install using:
     ```bash
     pip install reportlab
     ```

6. **`dpkt`**:
   - Library for decoding and encoding of network packets, useful for parsing captured data.
   - Install using:
     ```bash
     pip install dpkt
     ```

7. **`urllib3`**:
   - Handles HTTP requests and connections.
   - Install using:
     ```bash
     pip install urllib3
     ```

---

### Installation Command

You can create a `requirements.txt` file for easy installation of these dependencies:

```bash
dnspython
requests
Flask
Flask-Session
reportlab
dpkt
urllib3


