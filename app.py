from io import BytesIO
import dns.resolver
import dns.query
import dns.rdatatype
import dns.rdata
import dns.zone
import socket
import random
import string
from markupsafe import Markup

import dns.resolver
import collections
from ipaddress import IPv4Network, IPv6Network, AddressValueError
import requests
from requests import Session as RequestsSession  # Rename this to avoid conflict with Flask-Session
import threading
import traceback
from flask import Flask, render_template, request, make_response, session
from flask_session import Session  # Import Flask-Session
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib import colors
import os
import dpkt
import urllib3
import time
import re

# Disable InsecureRequestWarning for whois lookups
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(app.instance_path, 'session_data')
app.secret_key = os.urandom(32)
Session(app)  # Initialize the Flask-Session

# --- DNS Enumeration and Helper Functions from sample2.py ---

def get_ip_addresses(domain, nameserver="1.1.1.1", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout  # Set timeout for each individual query
        answers = resolver.resolve(domain, "A", lifetime=timeout)  # Overall timeout
        ip_addresses = [str(rdata.address) for rdata in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return []
    except dns.resolver.NoAnswer:
        print(f"No answer from DNS server for A records of domain: {domain}")
        return []
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except socket.error:
        print(f"Socket error occurred while resolving domain: {domain}")
        return []

import dns.resolver

# Function to resolve DNS queries with a higher timeout and retries
def resolve_domain(domain, retries=3):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1']  # Use Cloudflare's DNS server
    resolver.use_ipv6 = False  # Disable IPv6 for DNS queries
    resolver.lifetime = 50.0  
    attempts = 0

    while attempts < retries:
        try:
            answers = resolver.resolve(domain)
            ip_addresses = [str(rdata.address) for rdata in answers]
            return ip_addresses
        except dns.resolver.Timeout:
            attempts += 1
            print(f"DNS resolution timed out for domain: {domain}. Retrying... ({attempts}/{retries})")
        except dns.exception.DNSException as e:
            print(f"DNS resolution error for domain {domain}: {e}")
            break

    return [] 

def get_ns_records(domain, nameserver="8.8.8.8", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "NS", lifetime=timeout)
        ns_records = [str(rdata.target) for rdata in answers]
        return ns_records
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return []
    except dns.resolver.NoAnswer:
        print(f"No answer from DNS server for NS records of domain: {domain}")
        return []
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except socket.error:
        print(f"Socket error occurred while resolving domain: {domain}")
        return []


def get_mx_records(domain, nameserver="8.8.8.8", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "MX", lifetime=timeout)
        mx_records = [{"exchange": str(rdata.exchange), "preference": rdata.preference} for rdata in answers]
        return mx_records
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return []
    except dns.resolver.NoAnswer:
        print(f"No answer from DNS server for MX records of domain: {domain}")
        return []
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except socket.error:
        print(f"Socket error occurred while resolving domain: {domain}")
        return []


def get_srv_records(domain, nameserver="8.8.8.8", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "SRV", lifetime=timeout)
        srv_records = [
            {
                "name": str(rdata.name),
                "target": str(rdata.target),
                "port": rdata.port,
                "priority": rdata.priority,
                "weight": rdata.weight
            } for rdata in answers
        ]
        return srv_records
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return []
    except dns.resolver.NoAnswer:
        print(f"No answer from DNS server for SRV records of domain: {domain}")
        return []
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except socket.error:
        print(f"Socket error occurred while resolving domain: {domain}")
        return []


def get_txt_records(domain, nameserver="8.8.8.8", timeout=50.0):
    txt_records = []
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "TXT", lifetime=timeout)
        for rdata in answers:
            txt_data = " ".join([s.decode("utf-8") for s in rdata.strings])
            txt_records.append(txt_data)
    except dns.resolver.NoAnswer:
        print(f"No TXT records found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except Exception as e:
        print(f"Error querying TXT records for {domain}: {e}")
    return txt_records


def get_spf_records(domain, nameserver="8.8.8.8", timeout=50.0):
    spf_records = []
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "TXT", lifetime=timeout)
        for rdata in answers:
            for txt_string in rdata.strings:
                # Check if the TXT record contains SPF information
                if txt_string.startswith(b"v=spf1"):
                    spf_record = txt_string.decode("utf-8")
                    spf_records.append(spf_record)
    except dns.resolver.NoAnswer:
        print(f"No SPF records found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except Exception as e:
        print(f"Error querying SPF records for {domain}: {e}")
    return spf_records


def get_soa_records(domain, nameserver="8.8.8.8", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "SOA", lifetime=timeout)
        soa_records = [
            {
                "mname": str(rdata.mname),
                "rname": str(rdata.rname),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum,
            } for rdata in answers
        ]
        return soa_records
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return []
    except dns.resolver.NoAnswer:
        print(f"No answer from DNS server for SOA records of domain: {domain}")
        return []
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return []
    except socket.error:
        print(f"Socket error occurred while resolving domain: {domain}")
        return []


def check_wildcard(res, domain):
    try:
        random_string = "".join(
            random.choice(string.ascii_lowercase) for _ in range(8)
        )
        target = f"{random_string}.{domain}"
        answer = get_a_answer(res, target, res.nameservers[0], res.timeout)

        if answer is not None:
            for a in answer.authority:
                if a.rdtype == 5:
                    return True
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except (dns.resolver.NoAnswer, socket.error) as e:
        print(f"Error checking wildcard for {domain}: {e}")
        traceback.print_exc()
        return False


def get_a_answer(res, query, ns, timeout):
    res.nameservers = [ns]
    res.timeout = timeout
    try:
        answer = res.resolve(query)
        return answer
    except dns.resolver.NoAnswer:
        return None


def process_dns_traffic(pcap_file):
    """Processes a pcap file to extract DNS queries."""
    traffic = []
    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_UDP:
                    continue
                udp = ip.data
                if udp.sport != 53 and udp.dport != 53:
                    continue
                dns_pkt = dpkt.dns.DNS(udp.data)
                traffic.append(dns_pkt)
            except Exception as e:
                print(f"Error processing packet in {pcap_file}: {e}")
    return traffic


def get_nsec_type(domain, res):
    """
    Determines the NSEC type (NSEC or NSEC3) used for DNSSEC.
    """
    target = "0." + domain
    answer = get_a_answer(res, target, res.nameservers[0], res.timeout)
    if answer is not None:
        for a in answer.authority:
            if a.rdtype == 50:
                return "NSEC3"
            elif a.rdtype == 47:
                return "NSEC"
    return None  # Return None if no NSEC/NSEC3 record is found


def dns_sec_check(domain, res):
    """
    Checks and prints DNSSEC configuration for a domain.
    """
    try:
        # Remove the rdclass argument
        answer = res.resolve(domain, "DNSKEY")
        print(f"DNSSEC is configured for {domain}")
        nsectype = get_nsec_type(domain, res)
        print("DNSKEYs:")
        for rdata in answer:
            if rdata.flags == 256:
                key_type = "ZSK"
            if rdata.flags == 257:
                key_type = "KSk"
            print(
                f"\t{nsectype} {key_type} {algorithm_to_text(rdata.algorithm)} {dns.rdata._hexify(rdata.key)}" # type: ignore
            )
        return "DNSSEC is Configured"
    except dns.resolver.NXDOMAIN:
        print(f"Could not resolve domain: {domain}")
        return "DNSSEC is Not configured"
    except dns.resolver.NoNameservers:
        print(
            f"All nameservers failed to answer the DNSSEC query for {domain}"
        )
        return "DNSSEC is Not configured"
    except dns.exception.Timeout:
        print(
            "A timeout error occurred please make sure you can reach the target DNS Servers"
        )
        print(
            f"directly and requests are not being filtered. Increase the timeout from {res.timeout} second"
        )
        print("to a higher number with --lifetime <time> option.")
        return "DNSSEC is Not configured"
    except dns.resolver.NoAnswer:
        print(f"DNSSEC is not configured for {domain}")
        return "DNSSEC is Not configured"

def check_bindversion(res, ns_server, timeout):
    """
    Checks for BIND version on a nameserver.
    """
    version = ""
    request = dns.message.make_query("version.bind", "txt", "ch")
    try:
        response = res.query(
            request, ns_server, timeout=timeout, one_rr_per_rrset=True
        )
        if len(response.answer) > 0:
            version = response.answer[0].to_text().split(" ")[-1]
            print(f"\t Bind Version for {ns_server} {version}")
    except (
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoAnswer,
        socket.error,
        dns.query.BadResponse,
    ):
        pass
    return version


def check_recursive(res, ns_server, timeout):
    """
    Checks if a nameserver is recursive.
    """
    query = dns.message.make_query("www.google.com.", dns.rdatatype.NS)
    try:
        response = res.query(query, ns_server, timeout)
        recursion_flag_pattern = r"\.*RA\.*"
        flags = dns.flags.to_text(response.flags)
        result = re.findall(recursion_flag_pattern, flags)
        if result:
            print(f"\t Recursion enabled on NS Server {ns_server}")
        return True
    except (socket.error, dns.exception.Timeout):
        pass
    return False


def get_whois_nets(whois_data):
    """
    This function will take the text output of a Whois query and return a list
    of tuples containing the (start, end) of each network range found.
    """
    # Declare a list to hold the networks found.
    net_ranges = []
    # Lets use a Regular expression to grab the network ranges
    whois_net_range_pattern = (
        r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}\s*-\s*(?:[0-9]{1,3}\.){3}[0-9]{1,3})|((?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})"
    )
    net_range_match = re.findall(whois_net_range_pattern, whois_data)

    # for each net range found we create a tuple of start, end and append to a list.
    if len(net_range_match) > 0:
        for i in range(len(net_range_match)):
            if net_range_match[i][0] != "":
                split_range = net_range_match[i][0].split("-")
                start_ip = split_range[0].strip()
                end_ip = split_range[1].strip()
                net_ranges.append((start_ip, end_ip))
            else:
                cidr = net_range_match[i][1].strip()
                try:  # Try IPv4 first
                    net_ranges.append((str(IPv4Network(cidr)[0]), str(IPv4Network(cidr)[-1])))
                except AddressValueError:  # If not IPv4, try IPv6
                    net_ranges.append((str(IPv6Network(cidr)[0]), str(IPv6Network(cidr)[-1])))


    return net_ranges


def get_whois_orgname(whois_data):
    """
    This function will take the text output of a Whois query and return the
    Organization name if present or an empty list if not.
    """
    # Declare a list to hold the org names found.
    org_names = []
    # Lets use a Regular expression to grab the network ranges
    whois_orgname_pattern = r"OrgName:(.*)|organisation:(.*)|organization:(.*)|Organization:(.*)|organization-name:(.*)"
    org_name_match = re.findall(
        whois_orgname_pattern, whois_data, re.IGNORECASE
    )

    # for each net range found we create a tuple of start, end and append to a list.
    if org_name_match:
        for i in range(len(org_name_match)):
            for j in range(len(org_name_match[i])):
                if org_name_match[i][j] != "":
                    org_names.append(org_name_match[i][j].strip())
    return org_names


def scrape_bing(domain, verbose=False):
    """
    Uses Bing search engine to find subdomains of a given domain
    """
    print(f"Performing Bing enumeration for {domain}")
    subdomains = []
    # Create a list of search URLs to query Bing
    search_urls = [
        f"https://www.bing.com/search?q=site%3A*.{domain}",
        f"https://www.bing.com/search?q=site%3A{domain}&go=Submit&qs=bs&form=QBRE",
    ]
    # Iterate through the search URLs
    for url in search_urls:
        try:
            # Fetch the Bing search results page
            r = requests.get(url)
            if verbose:
                print(f"Response status from bing: {r.status_code}")
            # Use a regular expression to extract subdomains from the response text
            # Group 1 of the regex match will contain the subdomain
            matches = re.findall(
                r'<cite>(?:https?:\/\/)?(.*?)<\/cite>', r.text
            )
            for match in matches:
                # Extract the subdomain from the match
                subdomain = match.split("/")[0]
                # Add the subdomain to the list if it's not already there
                if subdomain not in subdomains:
                    if verbose:
                        print(f"Found subdomain: {subdomain}")
                    subdomains.append(subdomain.strip())
        except Exception as e:
            print(f"Error: {e}")
    # Return the list of unique subdomains
    return subdomains


def scrape_yandex(domain, verbose=False):
    """
    Uses Yandex search engine to find subdomains of a given domain
    """
    print(f"Performing Yandex enumeration for {domain}")
    subdomains = []
    # Construct the Yandex search URL
    url = f"https://yandex.com/search/?text=site%3A*.{domain}"
    try:
        # Make a request to Yandex search
        r = requests.get(url)
        if verbose:
            print(f"Response status from yandex: {r.status_code}")
        # Extract subdomains from the search results using regex
        # The regex pattern looks for URLs within specific HTML tags
        matches = re.findall(
            r'<a\s+class="path__item"\s+href="(?:https?:\/\/)?(.*?)"', r.text
        )
        for match in matches:
            # Split the URL by '/' and get the first part (domain)
            subdomain = match.split("/")[0]
            # Add the subdomain to the list if it's not already there
            if subdomain not in subdomains:
                if verbose:
                    print(f"Found subdomain: {subdomain}")
                subdomains.append(subdomain.strip())
    except Exception as e:
        print(f"Error: {e}")
    # Return the list of subdomains
    return subdomains

def scrape_crtsh(domain, verbose=False, retries=3, backoff_factor=2):
    """
    Scrapes crt.sh for subdomains of a given domain with retry logic.
    """
    print(f"Performing crt.sh enumeration for {domain}")
    subdomains = set()
    attempts = 0

    while attempts < retries:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.status_code == 503:
                print(
                    f"Error retrieving information from crt.sh: {r.status_code} (attempt {attempts+1}/{retries})"
                )
                sleep_time = backoff_factor ** attempts
                print(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
                attempts += 1
                continue

            if r.ok:
                for cert in r.json():
                    for name in cert.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.").rstrip(".")
                        if name and domain in name:
                            subdomains.add(name)
                if verbose:
                    print(f"Found {len(subdomains)} subdomains on crt.sh")
                return list(subdomains)  # Success!
            else:
                print(f"Error retrieving information from crt.sh: {r.status_code}")
                return list(subdomains)  # Return what we have
        except Exception as e:
            print(f"Error: {e}")
            return list(subdomains)  # Return what we have

    print(f"Failed to retrieve information from crt.sh after {retries} retries.")
    return list(subdomains)



def check_dnssec(domain, nameserver="8.8.8.8", timeout=50.0):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        
        # Query for DNSKEY records
        dnskey_answers = resolver.resolve(domain, 'DNSKEY', lifetime=timeout)
        if dnskey_answers:
            return 'DNSSEC Enabled'
    except dns.resolver.NoAnswer:
        print(f"No DNSSEC records found for {domain}")
        return 'DNSSEC Not Enabled'
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
        return 'Domain Not Found'
    except dns.exception.Timeout:
        print(f"DNS resolution timed out for domain: {domain}")
        return 'Timeout'
    except Exception as e:
        print(f"Error checking DNSSEC for {domain}: {e}")
        return 'Error'

    return 'DNSSEC Not Enabled'


def diff_zones(zone1, zone2):
    """Compare two DNS zones and return a list of changes."""
    changes = []
    # Create a set of records in each zone.
    records1 = set(zone1.iterate_rdatas())
    records2 = set(zone2.iterate_rdatas())
    # Find the records that are in zone1 but not in zone2.
    added = records1 - records2
    # Find the records that are in zone2 but not in zone1.
    removed = records2 - records1
    # Find the records that are in both zones but have different values.
    modified = {
        r
        for r in records1 & records2
        if r in zone1 and r in zone2 and zone1[r] != zone2[r]
    }
    # Add the changes to the list.
    changes.extend((r, "added") for r in added)
    changes.extend((r, "removed") for r in removed)
    changes.extend((r, "modified") for r in modified)
    return changes


def detect_zone_transfer_attack(traffic):
    """Detect zone transfer attacks in the given traffic."""
    # Look for DNS queries with the AXFR rdtype.
    axfr_queries = [
        q for q in traffic if q.question[0].rdtype == dns.rdatatype.AXFR
    ]
    # Check if there are a large number of AXFR queries from a single source.
    sources = collections.Counter(q.src for q in axfr_queries)
    if any(count > 100 for count in sources.values()):
        return True
    return False


def detect_key_rollover(dnskey_records):
    """Detect DNSSEC key rollovers in the given DNSKEY records."""
    # Extract the public keys from the DNSKEY records.
    keys = [rdata.key for rdata in dnskey_records]
    # Check if there are multiple keys with the same algorithm and key tag.
    key_tags = collections.Counter((key.algorithm, key.key_tag) for key in keys)
    if any(count > 1 for count in key_tags.values()):
        return True
    return False


class RateLimitedResolver(dns.resolver.Resolver):
    """A DNS resolver that rate limits zone transfer requests."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rate_limit = kwargs.get("rate_limit", 10)
        self.requests = collections.defaultdict(int)

    def query(self, *args, **kwargs):
        # Check if the request is a zone transfer request.
        if kwargs.get("rdtype") == dns.rdatatype.AXFR:
            # Check if the rate limit has been exceeded.
            if self.requests[kwargs["qname"]] >= self.rate_limit:
                raise dns.resolver.NoAnswer
            # Increment the request count for the domain.
            self.requests[kwargs["qname"]] += 1
        # Perform the query.
        return super().query(*args, **kwargs)

    def get_a(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.A, **kwargs)

    def get_ns(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.NS, **kwargs)

    def get_mx(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.MX, **kwargs)

    def get_soa(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.SOA, **kwargs)

    def get_txt(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.TXT, **kwargs)

    def get_srv(self, qname, **kwargs):
        return self.resolve(qname, rdtype=dns.rdatatype.SRV, **kwargs)

    def zone_transfer(self):
        """Attempts a zone transfer (AXFR) for the domain."""
        try:
            z = dns.zone.from_xfr(
                dns.query.xfr(
                    self.nameservers[0], self.domain, lifetime=self.timeout
                )
            )
            return [
                {
                    "type": "SOA",
                    "mname": z.origin.to_text(),
                    "address": socket.gethostbyname(z.nameservers[0].to_text()),
                }
            ]
        except dns.exception.FormError:
            print(
                "Zone transfer failed. The server may not allow zone transfers."
            )
            return None
        except (socket.gaierror, socket.error) as e:
            print(
                f"An error occurred while performing the zone transfer: {e}"
            )
            return None


def brute_domain(resolver, domain_list, domain, filter_wildcard=False, verbose=False, ignore_wildcard_rr=False, thread_num=5):
    """
    Performs a DNS brute force attack against a domain using a given wordlist.
    """

    results = []
    wildcard_ip = None
    if filter_wildcard:
        wildcard_ip = check_wildcard(resolver, domain)
        if wildcard_ip:
            print(f"Wildcard resolution is enabled for {domain} filtering results based on IP address.")
        else:
            print(f"Wildcard resolution is not enabled for {domain}, disabling wildcard filtering.")
            wildcard_ip = None

    def brute_domain_thread(chunk, results):
        for entry in chunk:
            try:
                # If the entry doesn't end with a dot, assume it's a subdomain
                if not entry.endswith("."):
                    hostname = f"{entry}.{domain}"
                else:
                    hostname = entry

                # Get the A record for the hostname
                answer = resolver.resolve(hostname, "A")
                if answer:
                    for rdata in answer:
                        if (not filter_wildcard or rdata.address not in wildcard_ip):
                            with threading.Lock():  # Acquire lock before modifying results
                                results.append({
                                    "type": "A",
                                    "name": hostname,
                                    "address": str(rdata.address),  # Convert IPAddress object to string
                                })
                            if verbose:
                                print(f"Found A record: {hostname} - {rdata.address}")

                # Get the CNAME record for the hostname
                answer = resolver.resolve(hostname, "CNAME")
                if answer:
                    for rdata in answer:
                        with threading.Lock():
                            results.append({
                                "type": "CNAME",
                                "name": hostname,
                                "target": str(rdata.target),
                            })
                        if verbose:
                            print(f"Found CNAME record: {hostname} - {rdata.target}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                print(f"Error: {e}")

    # Create threads to speed up the brute force process
    threads = []
    chunk_size = len(domain_list) // thread_num
    domain_chunks = [domain_list[i:i + chunk_size] for i in range(0, len(domain_list), chunk_size)]
    for chunk in domain_chunks:
        thread = threading.Thread(target=brute_domain_thread, args=(chunk, results))  # Pass results to the thread
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    return results


# --- Flask Routes ---
@app.route('/dns_query', methods=['POST'])
def dns_query():
    domain = request.form.get('domain')
    print(f"Querying DNS for domain: {domain}")

    # Use the updated resolver function with retries
    ip_addresses = resolve_domain(domain)

    if ip_addresses:
        print(f"IP addresses for {domain}: {ip_addresses}")
    else:
        print(f"Failed to resolve DNS for {domain}")

    return render_template('results.html', domain=domain, ip_addresses=ip_addresses)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = {}  # Initialize an empty dictionary to store results
    if request.method == 'POST':
        domain = request.form.get('domain')
        nameserver = request.form.get('nameserver', '8.8.8.8')
        request_timeout = float(request.form.get('timeout', 10.0))  
        wordlist_path = request.form.get('wordlist_path')
        search_engines = request.form.getlist('search_engine')
        zone1_path = request.form.get('zone1_path')
        zone2_path = request.form.get('zone2_path')
        traffic_file = request.form.get('traffic_file')
        filter_wildcard = request.form.get('filter_wildcard') == 'on'  # Check if checkbox is checked

        if not domain:
            return render_template('index.html', error="Please enter a domain name.")

        try:
            res = RateLimitedResolver(configure=False)
            if nameserver:
                res.nameservers = [nameserver]
            res.timeout = request_timeout

            # --- DNS Enumeration ---
            results = {
                'domain': domain,
                'ip_addresses': get_ip_addresses(domain, nameserver, request_timeout),
                'ns_records': get_ns_records(domain, nameserver, request_timeout),
                'mx_records': get_mx_records(domain, nameserver, request_timeout),
                'soa_records': get_soa_records(domain, nameserver, request_timeout),
                'txt_records': get_txt_records(domain, nameserver, request_timeout),
                'spf_records': get_spf_records(domain, nameserver, request_timeout),
                'srv_records': get_srv_records(domain, nameserver, request_timeout),
                'wildcard_enabled': check_wildcard(res, domain)
            }

            # --- Brute Force ---
            if wordlist_path:
                wordlist_path = wordlist_path.strip('"')
                try:
                    with open(wordlist_path, 'r') as f:
                        domain_list = [line.strip() for line in f]
                    results['bruteforce_results'] = brute_domain(
                        res, domain_list, domain,
                        filter_wildcard=filter_wildcard,  # Pass filter_wildcard to brute_domain
                        thread_num=5  # Adjust as needed
                    )
                except FileNotFoundError:
                    return render_template('index.html', error="Wordlist not found.")

            # --- Search Engine Enumeration ---
            search_engine_results = {}
            if 'bing' in search_engines:
                search_engine_results['bing'] = scrape_bing(domain)
            if 'yandex' in search_engines:
                search_engine_results['yandex'] = scrape_yandex(domain)
            if 'crtsh' in search_engines:
                search_engine_results['crtsh'] = scrape_crtsh(domain)
            results['search_engine_results'] = search_engine_results

            # --- Additional Checks from sample2.py ---
            # - DNSSEC Check (using dns_sec_check)
            results['dnssec_status'] = dns_sec_check(domain, res)

            # - Zone Transfer Attack Detection (using traffic_file and detect_zone_transfer_attack)
            if traffic_file:
                traffic = process_dns_traffic(traffic_file)
                results['zone_transfer_attack'] = detect_zone_transfer_attack(traffic)

            # - Key Rollover Detection (using detect_key_rollover)
            try:
                dnskey_records = res.resolve(domain, "DNSKEY")
                results['key_rollover'] = detect_key_rollover(dnskey_records)
            except dns.resolver.NoAnswer:
                results['key_rollover'] = (
                    "DNSSEC is not configured for this domain, skipping key rollover detection."
                )

            # - Zone Diffing (using zone1)
            if zone1_path and zone2_path:
               try:
                   zone1 = dns.zone.from_file(zone1_path, domain)
                   zone2 = dns.zone.from_file(zone2_path, domain)
                   results['zone_diff'] = diff_zones(zone1, zone2)
               except Exception as e:
                   results['zone_diff'] = f"Error performing zone diffing: {e}"

            # Store results in session for PDF generation
            session['results'] = results

        except Exception as e:
            return render_template('index.html', error=f"An error occurred: {e}")

    return render_template('index.html', results=results)
@app.route('/', methods=['GET', 'POST'])
def dns_enumeration():
    if request.method == 'POST':
        domain = request.form['domain']
        print(f"Domain received: {domain}")  # Debug print

        session['results'] = {
                'domain': domain,
                'ip_addresses': get_ip_addresses(domain),
                'ns_records': get_ns_records(domain),
                'mx_records': get_mx_records(domain),
                'srv_records': get_srv_records(domain),
                'txt_records': get_txt_records(domain),
                'spf_records': get_spf_records(domain),
                'soa_records': get_soa_records(domain),
                'wildcard_enabled': check_wildcard(domain),
                'dnssec_status': check_dnssec(domain),  # Add DNSSEC check here
                'search_engine_results': {
                    'bing': ['sub.example.com', 'test.example.com'],  # Simulated data
                    'yandex': ['sub1.example.com'],
                    'crtsh': ['sub2.example.com']
                },
                'bruteforce_results': [{'type': 'A', 'name': 'www.example.com', 'address': '192.0.2.1'}]  # Simulated data
            }


        # Debug prints to verify DNS query results
        print(f"IP Addresses: {session['results']['ip_addresses']}")
        print(f"NS Records: {session['results']['ns_records']}")
        print(f"MX Records: {session['results']['mx_records']}")
        
        print("Session data in dns_enumeration:", session['results'])
        return render_template('index.html', results=session['results'])
        # return render_template('index.html', results=session['results']) 

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    print("Session data in generate_pdf:", session.get('results', {}))
    results = session.get('results', {})
    domain = results.get('domain', "Unknown Domain")
    nameserver = request.form.get('nameserver', '8.8.8.8')  # Get nameserver from form

    if not results:
        return render_template('index.html', error="No results to generate PDF.")

    try:
        # Debugging - print the data that will be added to the PDF
        print(f"Results: {results}")

        # Setup PDF document and styles
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        style_title = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            alignment=1,  # Center alignment
            spaceAfter=20
        )
        style_normal = styles['Normal']
        style_record_heading = ParagraphStyle(
            'RecordHeading',
            parent=styles['Heading2'],
            fontSize=12,
            spaceBefore=12,
        )
        style_record_data = ParagraphStyle(
            'RecordData',
            parent=styles['Normal'],
            fontSize=10,
        )
        story = [Paragraph(f"DNS Enumeration Report for {domain}", style_title)]

        # Function to add sections to the PDF
        def sanitize_text(text):
            # Remove any malformed tags and ensure proper closing tags
            # Example: Replace <strong> without a closing tag
            text = re.sub(r"<strong>(.*?)</para>", r"<strong>\1</strong></para>", text)
            return Markup(text)  # Return sanitized text with proper HTML escaping
        def add_section(title, data, record_type="simple"):
            """
            Adds a section to the PDF report.

            Args:
                title (str): The title of the section.
                data (list): The data to be included in the section. Can be a simple list or a list of dictionaries.
                record_type (str, optional): The type of data. Can be "simple" for a list of strings, 
                                            or "table" for a list of dictionaries. Defaults to "simple".
            """
            story.append(Paragraph(title, style_record_heading))
            
            if data:
                if record_type == "table":
                    table_data = []

                    # Check if the data is a list of dictionaries (for table-like structure)
                    if isinstance(data[0], dict): 
                        headers = data[0].keys()
                        table_data.append([Paragraph(header, style_record_data) for header in headers])
                        
                        # Iterate through each item (dictionary) in the data
                        for item in data:
                            # Extract values for each header, handling cases where a key might be missing
                            row = [str(item.get(key, '')) for key in headers]  
                            table_data.append(row)
                    else:
                        # Handle simple lists (each item is a string)
                        table_data = [[Paragraph(str(item), style_record_data)] for item in data]  

                    # Create the table and apply styling
                    table = Table(table_data, colWidths=[100, 100, 100, 100])  # Adjust column widths as needed
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(table) 
                else:
                    # Handle simple data (list of strings or similar)
                    for item in data:
                        if isinstance(item, dict):
                            # If the item is a dictionary, iterate through key-value pairs
                            for key, value in item.items():
                                story.append(Paragraph(f"{key}: {value}", style_record_data))
                        else:
                            # Otherwise, treat the item as a simple string
                            story.append(Paragraph(str(item), style_record_data))
            else:
                # If there is no data for the section, add a message 
                story.append(Paragraph("No records found.", style_record_data))
            
            # Add spacing between sections
            story.append(Spacer(1, 20)) 

        # Add Domain Information
        domain_info_table_data = [
            ["Domain:", domain],
            ["Nameserver:", nameserver],
        ]
        domain_info_table = Table(domain_info_table_data, colWidths=[100, 300])
        domain_info_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(domain_info_table)
        story.append(Spacer(1, 24))

        # Add each section to the PDF
        add_section("IP Addresses", results.get('ip_addresses', []))
        add_section("NS Records", results.get('ns_records', []))
        add_section("MX Records", results.get('mx_records', []))
        add_section("SOA Records", results.get('soa_records', []))
        add_section("TXT Records", results.get('txt_records', []))
        add_section("SPF Records", results.get('spf_records', []))
        add_section("SRV Records", results.get('srv_records', []))
        add_section("Brute Force Results", results.get('bruteforce_results', []), record_type="table")

        # Add Search Engine Results
        search_engine_results = results.get('search_engine_results', {})
        for engine, data in search_engine_results.items():
            add_section(f"{engine.capitalize()} Results", data)

        # Add other checks
        add_section("DNSSEC Status", [results.get('dnssec_status', 'Not checked')])
        add_section("Zone Transfer Attack Detection", [results.get('zone_transfer_attack', 'Not checked')])
        add_section("Key Rollover Detection", [results.get('key_rollover', 'Not checked')])
        add_section("Zone Diffing", results.get('zone_diff', []))

        # Build the PDF document
        doc.build(story)

        # Send the PDF as a response
        pdf_buffer.seek(0)
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=dns_enumeration_report.pdf'
        response.headers['Content-Type'] = 'application/pdf'
        return response

    except Exception as e:
        # Handle exceptions and return the error page
        return render_template('index.html', error=f"An error occurred while generating the PDF: {e}")

if __name__ == '__main__':
    app.run(debug=True)