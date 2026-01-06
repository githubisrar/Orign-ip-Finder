#!/usr/bin/env python3
import argparse
import dns.resolver
import requests
import socket
import ssl
import time
import random
import json
import os
import re
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import ipaddress
import dns.reversename
import dns.exception
import whois
from datetime import datetime

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# Configuration
MAX_THREADS = 50
TIMEOUT = 10
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
]

class AdvancedSubdomainFinder:
    def __init__(self, domain, output_file=None, threads=MAX_THREADS, verbose=False):
        self.domain = domain
        self.output_file = output_file
        self.threads = threads
        self.verbose = verbose
        self.found_subdomains = set()
        self.found_ips = set()
        self.cloudflare_ranges = self._load_cloudflare_ranges()
        self.waf_detected = False
        self.cdn_providers = self._load_cdn_providers()
        self.resolver = self._init_dns_resolver()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = False
        self.wordlist = self._load_wordlist()
        
    def _init_dns_resolver(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [
            '8.8.8.8', '8.8.4.4',         # Google
            '1.1.1.1', '1.0.0.1',         # Cloudflare
            '9.9.9.9', '149.112.112.112', # Quad9
            '208.67.222.222', '208.67.220.220' # OpenDNS
        ]
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        return resolver
    
    def _load_cloudflare_ranges(self):
        return [
            '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
            '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
            '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
            '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
        ]
    
    def _load_cdn_providers(self):
        return {
            'cloudflare': ['cloudflare'],
            'akamai': ['akamai', 'akamaiedge', 'akamaihd'],
            'fastly': ['fastly', 'fastlylb'],
            'cloudfront': ['cloudfront'],
            'incapsula': ['incapdns']
        }
    
    def _load_wordlist(self):
        default_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
            'cdn', 'api', 'dev', 'test', 'staging', 'secure', 'vpn', 'm', 'mobile',
            'blog', 'shop', 'store', 'app', 'apps', 'cloud', 'support', 'status',
            'portal', 'demo', 'beta', 'alpha', 'new', 'old', 'backup', 'mx',
            'static', 'media', 'assets', 'cdn1', 'cdn2', 'origin', 'internal',
            'external', 'proxy', 'gateway', 'router', 'fw', 'firewall', 'dmz',
            'intranet', 'extranet', 'server', 'servers', 'db', 'database',
            'sql', 'mysql', 'oracle', 'mssql', 'postgres', 'mongodb', 'redis',
            'elasticsearch', 'kibana', 'grafana', 'prometheus', 'jenkins',
            'git', 'github', 'gitlab', 'bitbucket', 'jira', 'confluence',
            'wiki', 'documentation', 'docs', 'help', 'kb', 'knowledgebase',
            'forum', 'forums', 'community', 'chat', 'messaging', 'email',
            'web', 'web1', 'web2', 'web3', 'web4', 'web5', 'web6', 'web7',
            'web8', 'web9', 'web10', 'owa', 'exchange', 'outlook', 'imap',
            'pop3', 'smtp', 'ldap', 'ldaps', 'ad', 'ads', 'adserver', 'adfs',
            'sso', 'auth', 'authentication', 'login', 'logout', 'signin',
            'signout', 'register', 'registration', 'account', 'accounts',
            'billing', 'invoice', 'payment', 'payments', 'checkout', 'cart',
            'shop', 'store', 'ecommerce', 'pos', 'pointofsale', 'inventory',
            'crm', 'erp', 'hr', 'humanresources', 'payroll', 'accounting',
            'finance', 'tax', 'legal', 'compliance', 'security', 'secure',
            'vpn', 'remote', 'ssh', 'ftp', 'sftp', 'scp', 'rsync', 'backup',
            'backups', 'archive', 'archives', 'storage', 'storages', 'fs',
            'files', 'file', 'fileserver', 'fileshare', 'share', 'shares',
            'nas', 'san', 'iscsi', 'nfs', 'smb', 'cifs', 'webdav', 'dav',
            'svn', 'cvs', 'hg', 'bzr', 'p4', 'perforce', 'tfs', 'vss',
            'vsts', 'azure', 'aws', 'gcp', 'google', 'ibm', 'oracle',
            'salesforce', 'dynamics', 'office', 'office365', 'sharepoint',
            'teams', 'skype', 'lync', 'zoom', 'webex', 'gotomeeting',
            'gotowebinar', 'join', 'joinme', 'teamviewer', 'anydesk',
            'vnc', 'rdp', 'remote desktop', 'remotedesktop', 'terminal',
            'terminalserver', 'ts', 'citrix', 'xenapp', 'xendesktop',
            'vmware', 'vsphere', 'esxi', 'hyperv', 'kvm', 'xen', 'docker',
            'kubernetes', 'k8s', 'openshift', 'rancher', 'mesos', 'nomad',
            'swarm', 'consul', 'etcd', 'zookeeper', 'kafka', 'rabbitmq',
            'activemq', 'artemis', 'nats', 'redis', 'memcached', 'couchbase',
            'mongodb', 'postgres', 'mysql', 'mariadb', 'oracle', 'sqlserver',
            'db2', 'cassandra', 'dynamodb', 'cosmosdb', 'firestore',
            'firebase', 'realtime', 'realtimedb', 'bigtable', 'spanner',
            'cockroachdb', 'yugabyte', 'tidb', 'vitess', 'scylla',
            'arangodb', 'neo4j', 'orientdb', 'janusgraph', 'dgraph',
            'arangodb', 'fauna', 'rethinkdb', 'couchdb', 'pouchdb',
            'ravendb', 'ravendb', 'ravendb', 'ravendb', 'ravendb', 'ravendb'
        ]
        
        # Try to load from file if exists
        if os.path.exists('subdomains.txt'):
            with open('subdomains.txt', 'r') as f:
                return list(set(default_wordlist + [line.strip() for line in f if line.strip()]))
        return default_wordlist
    
    def log(self, message, level="info"):
        if self.verbose or level in ("warning", "error", "critical"):
            prefix = {
                "info": "[*]",
                "warning": "[!]",
                "error": "[-]",
                "critical": "[X]",
                "success": "[+]"
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def save_results(self):
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(f"# Subdomain scan results for {self.domain}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total subdomains found: {len(self.found_subdomains)}\n")
                f.write(f"# Total unique IPs found: {len(self.found_ips)}\n\n")
                
                f.write("\n[SUBDOMAINS]\n")
                for subdomain in sorted(self.found_subdomains):
                    f.write(f"{subdomain}\n")
                
                f.write("\n[IP ADDRESSES]\n")
                for ip in sorted(self.found_ips):
                    f.write(f"{ip}\n")
            
            self.log(f"Results saved to {self.output_file}", "success")
    
    def is_cloudflare_ip(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for network in self.cloudflare_ranges:
                if ip_addr in ipaddress.ip_network(network):
                    return True
        except ValueError:
            pass
        return False
    
    def is_cdn_ip(self, ip, domain):
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            for provider, patterns in self.cdn_providers.items():
                if any(p in hostname for p in patterns):
                    self.log(f"IP {ip} belongs to {provider} CDN", "warning")
                    return True
        except (socket.herror, socket.gaierror):
            pass
        
        # Check reverse DNS
        try:
            rev_name = dns.reversename.from_address(ip)
            rev_dns = str(self.resolver.resolve(rev_name, 'PTR')[0]).rstrip('.')
            for provider, patterns in self.cdn_providers.items():
                if any(p in rev_dns.lower() for p in patterns):
                    self.log(f"IP {ip} belongs to {provider} CDN (via rDNS)", "warning")
                    return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        
        return False
    
    def dns_query(self, subdomain, record_type='A'):
        target = f"{subdomain}.{self.domain}" if subdomain else self.domain
        try:
            answers = self.resolver.resolve(target, record_type)
            results = []
            for answer in answers:
                if record_type == 'A':
                    results.append(answer.address)
                    if not self.is_cloudflare_ip(answer.address) and not self.is_cdn_ip(answer.address, target):
                        self.found_ips.add(answer.address)
                elif record_type == 'CNAME':
                    results.append(str(answer.target).rstrip('.'))
            return target, results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception as e:
            self.log(f"Error querying {target} ({record_type}): {str(e)}", "error")
            return None
    
    def brute_force_subdomains(self):
        self.log(f"Starting subdomain brute force with {len(self.wordlist)} words")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for sub in self.wordlist:
                futures.append(executor.submit(self.dns_query, sub))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ips = result
                    self.found_subdomains.add(subdomain)
                    self.log(f"Found: {subdomain} -> {', '.join(ips)}", "success")
        
        self.log(f"Brute force completed. Found {len(self.found_subdomains)} subdomains", "success")
        return self.found_subdomains
    
    def check_certificate_transparency(self):
        self.log("Checking certificate transparency logs...")
        sources = [
            ('crt.sh', f"https://crt.sh/?q=%.{self.domain}&output=json"),
            ('entrust', f"https://ct.googleapis.com/logs/argon2021/ct/v1/get-entries?domain={self.domain}"),
            ('google', f"https://ct.googleapis.com/logs/argon2022/ct/v1/get-entries?domain={self.domain}")
        ]
        
        for name, url in sources:
            try:
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                response = self.session.get(url, headers=headers, timeout=TIMEOUT)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for entry in data:
                                self._process_ct_entry(entry, name)
                        elif isinstance(data, dict):
                            self._process_ct_entry(data, name)
                        else:
                            # Try line by line
                            for line in response.text.split('\n'):
                                if line.strip():
                                    try:
                                        entry = json.loads(line.strip())
                                        self._process_ct_entry(entry, name)
                                    except json.JSONDecodeError:
                                        pass
                    except json.JSONDecodeError:
                        self.log(f"Invalid JSON from {name}", "warning")
            except Exception as e:
                self.log(f"Error checking {name} CT logs: {str(e)}", "error")
    
    def _process_ct_entry(self, entry, source):
        names = []
        if 'name_value' in entry:
            names.append(entry['name_value'])
        if 'common_name' in entry:
            names.append(entry['common_name'])
        if 'dns_names' in entry and isinstance(entry['dns_names'], list):
            names.extend(entry['dns_names'])
        
        for name in names:
            if isinstance(name, str):
                if '\n' in name:
                    for subname in name.split('\n'):
                        self._add_subdomain(subname.strip(), source)
                else:
                    self._add_subdomain(name.strip(), source)
    
    def _add_subdomain(self, name, source):
        name = name.lower().strip()
        if name.startswith('*.'):
            name = name[2:]
        
        if self.domain in name and name.endswith(self.domain):
            if name not in self.found_subdomains:
                self.found_subdomains.add(name)
                self.log(f"Found via {source} CT logs: {name}", "success")
                # Resolve the new subdomain
                self.dns_query(name.replace(f".{self.domain}", ""))
    
    def check_dns_records(self):
        self.log("Checking various DNS records...")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                result = self.dns_query('', record_type)
                if result:
                    target, records = result
                    self.log(f"Found {record_type} records for {target}: {', '.join(records)}", "success")
            except Exception as e:
                self.log(f"Error checking {record_type} records: {str(e)}", "error")
    
    def check_security_headers(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            response = self.session.get(url, timeout=TIMEOUT)
            
            # Check for WAF headers
            waf_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
                'akamai': ['akamai', 'x-akamai'],
                'incapsula': ['incap-sid', 'x-iinfo'],
                'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
                'aws': ['x-amz-cf-pop', 'x-amz-cf-id'],
                'barracuda': ['barracuda'],
                'fortinet': ['fortigate'],
                'imperva': ['x-cdn', 'x-imperva']
            }
            
            server_header = response.headers.get('Server', '').lower()
            for waf, indicators in waf_indicators.items():
                if any(ind.lower() in server_header for ind in indicators):
                    self.waf_detected = True
                    self.log(f"Detected {waf} WAF via Server header", "warning")
                    return True
                
                for header in response.headers:
                    if any(ind.lower() in header.lower() for ind in indicators):
                        self.waf_detected = True
                        self.log(f"Detected {waf} WAF via {header} header", "warning")
                        return True
            
            # Check for other security headers
            security_headers = [
                'x-xss-protection', 'x-content-type-options',
                'x-frame-options', 'content-security-policy',
                'strict-transport-security', 'x-permitted-cross-domain-policies'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    self.log(f"Security header found: {header}", "info")
            
            return False
        except Exception as e:
            self.log(f"Error checking security headers: {str(e)}", "error")
            return False
    
    def find_origin_ip(self):
        self.log("Attempting to find origin IP...")
        
        techniques = [
            self._check_dns_history,
            self._check_old_website_versions,
            self._check_misconfigured_dns,
            self._check_subdomains_for_origin,
            self._check_ssl_cert_ip,
            self._check_cloudflare_workers,
            self._check_github_leaks,
            self._check_whois_history,
            self._check_asn_info,
            self._check_headers_for_ip_leaks,
            self._check_sitemap,
            self._check_robots_txt,
            self._check_dns_zone_transfer,
            self._check_common_vhosts,
            self._check_historical_ip_data
        ]
        
        origin_ips = set()
        
        for technique in techniques:
            try:
                result = technique()
                if result:
                    if isinstance(result, list):
                        for ip in result:
                            if not self.is_cloudflare_ip(ip) and not self.is_cdn_ip(ip, self.domain):
                                origin_ips.add(ip)
                                self.log(f"Potential origin IP found via {technique.__name__}: {ip}", "success")
                    else:
                        if not self.is_cloudflare_ip(result) and not self.is_cdn_ip(result, self.domain):
                            origin_ips.add(result)
                            self.log(f"Potential origin IP found via {technique.__name__}: {result}", "success")
            except Exception as e:
                self.log(f"Error in technique {technique.__name__}: {str(e)}", "error")
                continue
        
        return origin_ips
    
    def _check_dns_history(self):
        self.log("Checking DNS history...")
        services = [
            ('viewdns', f"https://api.viewdns.info/dnsrecord/?domain={self.domain}&apikey=demo&output=json"),
            ('securitytrails', f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"),
            ('whoisxmlapi', f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={self.domain}&outputFormat=JSON"),
            ('hackertarget', f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
        ]
        
        ips = set()
        
        for name, url in services:
            try:
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                response = self.session.get(url, headers=headers, timeout=TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    if name == 'viewdns':
                        for record in data.get('response', {}).get('records', []):
                            if record.get('type') == 'A':
                                ips.add(record.get('address'))
                    elif name == 'securitytrails':
                        for record in data.get('records', []):
                            for value in record.get('values', []):
                                ips.add(value.get('ip'))
                    elif name == 'whoisxmlapi':
                        for record in data.get('WhoisRecord', {}).get('audit', {}).get('createdDate', []):
                            if 'ip' in record.lower():
                                ips.update(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', record))
                    elif name == 'hackertarget':
                        for line in response.text.split('\n'):
                            if ',' in line:
                                ip = line.split(',')[1].strip()
                                if ip:
                                    ips.add(ip)
            except Exception as e:
                self.log(f"Error checking {name} DNS history: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_old_website_versions(self):
        self.log("Checking old website versions...")
        ips = set()
        
        # Check Archive.org
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&collapse=urlkey"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT*2)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if 'cloudflare' not in entry[0].lower():
                        parsed = urlparse(entry[0])
                        if parsed.netloc and parsed.netloc != self.domain:
                            try:
                                ip = socket.gethostbyname(parsed.netloc)
                                ips.add(ip)
                                self.log(f"Found potential origin from archive: {parsed.netloc} -> {ip}", "success")
                            except:
                                continue
        except Exception as e:
            self.log(f"Error checking old versions: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_misconfigured_dns(self):
        self.log("Checking for misconfigured DNS records...")
        ips = set()
        
        # Check common misconfigurations
        targets = [
            f"direct.{self.domain}", f"origin.{self.domain}", f"real.{self.domain}",
            f"backend.{self.domain}", f"internal.{self.domain}", f"prod.{self.domain}",
            f"dev.{self.domain}", f"staging.{self.domain}", f"api.{self.domain}",
            f"assets.{self.domain}", f"static.{self.domain}", f"media.{self.domain}"
        ]
        
        for target in targets:
            try:
                result = self.dns_query(target.replace(f".{self.domain}", ""))
                if result:
                    subdomain, addresses = result
                    for ip in addresses:
                        ips.add(ip)
                        self.log(f"Found via misconfigured DNS: {subdomain} -> {ip}", "success")
            except:
                continue
        
        return list(ips) if ips else None
    
    def _check_subdomains_for_origin(self):
        self.log("Checking found subdomains for origin IP...")
        ips = set()
        
        for subdomain in self.found_subdomains:
            try:
                # Skip common CDN domains
                if any(cdn in subdomain for cdn in ['cdn', 'cloudfront', 'akamai', 'fastly', 'incapdns']):
                    continue
                    
                result = self.dns_query(subdomain.replace(f".{self.domain}", ""))
                if result:
                    _, addresses = result
                    for ip in addresses:
                        if not self.is_cloudflare_ip(ip) and not self.is_cdn_ip(ip, subdomain):
                            ips.add(ip)
                            self.log(f"Potential origin from subdomain {subdomain}: {ip}", "success")
            except:
                continue
                
        return list(ips) if ips else None
    
    def _check_ssl_cert_ip(self):
        self.log("Checking SSL certificate for IP addresses...")
        ips = set()
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
            # Check subjectAltName for IP addresses
            for field in cert.get('subjectAltName', []):
                if field[0] == 'IP Address':
                    ip = field[1]
                    if not self.is_cloudflare_ip(ip):
                        ips.add(ip)
                        self.log(f"Found IP in SSL cert: {ip}", "success")
        except Exception as e:
            self.log(f"Error checking SSL cert: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_cloudflare_workers(self):
        self.log("Checking for exposed Cloudflare Workers...")
        ips = set()
        
        try:
            url = f"https://{self.domain}/cdn-cgi/trace"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            
            if response.status_code == 200 and 'ip=' in response.text:
                for line in response.text.split('\n'):
                    if line.startswith('ip='):
                        ip = line.split('=')[1]
                        if not self.is_cloudflare_ip(ip):
                            ips.add(ip)
                            self.log(f"Found potential origin IP via Cloudflare Worker: {ip}", "success")
        except Exception as e:
            self.log(f"Error checking Cloudflare Workers: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_github_leaks(self):
        self.log("Checking GitHub for potential leaks...")
        ips = set()
        
        try:
            url = f"https://api.github.com/search/code?q={self.domain}+in:file"
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'application/vnd.github.v3+json'
            }
            response = self.session.get(url, headers=headers, timeout=TIMEOUT*2)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    if any(ext in item['html_url'] for ext in ['.php', '.js', '.env', '.config', '.yml', '.yaml', '.json']):
                        try:
                            file_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                            file_response = self.session.get(file_url, headers=headers, timeout=TIMEOUT)
                            if file_response.status_code == 200:
                                ips.update(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', file_response.text))
                        except:
                            continue
        except Exception as e:
            self.log(f"Error checking GitHub: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_whois_history(self):
        self.log("Checking WHOIS history...")
        ips = set()
        
        try:
            w = whois.whois(self.domain)
            
            # Check nameservers
            if isinstance(w.name_servers, list):
                for ns in w.name_servers:
                    try:
                        result = socket.gethostbyname(ns)
                        ips.add(result)
                    except:
                        continue
            
            # Check registrar and other fields for IPs
            whois_text = str(w)
            ips.update(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', whois_text))
        except Exception as e:
            self.log(f"Error checking WHOIS: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_asn_info(self):
        self.log("Checking ASN information...")
        ips = set()
        
        try:
            url = f"https://api.hackertarget.com/aslookup/?q={self.domain}"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            if ip and ip != 'NA':
                                ips.add(ip)
        except Exception as e:
            self.log(f"Error checking ASN info: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_headers_for_ip_leaks(self):
        self.log("Checking HTTP headers for IP leaks...")
        ips = set()
        
        try:
            url = f"https://{self.domain}"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            
            # Check all headers for IP addresses
            for header, value in response.headers.items():
                found_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value)
                for ip in found_ips:
                    if not self.is_cloudflare_ip(ip):
                        ips.add(ip)
            
            # Check response body too
            found_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response.text)
            for ip in found_ips:
                if not self.is_cloudflare_ip(ip):
                    ips.add(ip)
        except Exception as e:
            self.log(f"Error checking headers: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_sitemap(self):
        self.log("Checking sitemap.xml for internal links...")
        ips = set()
        
        try:
            url = f"https://{self.domain}/sitemap.xml"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.content)
                    for url in root.findall('{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                        loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                        if loc is not None:
                            parsed = urlparse(loc.text)
                            if parsed.netloc and parsed.netloc != self.domain:
                                try:
                                    ip = socket.gethostbyname(parsed.netloc)
                                    ips.add(ip)
                                except:
                                    continue
                except ET.ParseError:
                    # Try to parse as text
                    for line in response.text.split('\n'):
                        if '<loc>' in line:
                            match = re.search(r'<loc>(.*?)</loc>', line)
                            if match:
                                parsed = urlparse(match.group(1))
                                if parsed.netloc and parsed.netloc != self.domain:
                                    try:
                                        ip = socket.gethostbyname(parsed.netloc)
                                        ips.add(ip)
                                    except:
                                        continue
        except Exception as e:
            self.log(f"Error checking sitemap: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_robots_txt(self):
        self.log("Checking robots.txt for internal links...")
        ips = set()
        
        try:
            url = f"https://{self.domain}/robots.txt"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.lower().startswith(('allow:', 'disallow:', 'sitemap:')):
                        parts = line.split(':')
                        if len(parts) > 1:
                            path = parts[1].strip()
                            if path.startswith('http'):
                                parsed = urlparse(path)
                                if parsed.netloc and parsed.netloc != self.domain:
                                    try:
                                        ip = socket.gethostbyname(parsed.netloc)
                                        ips.add(ip)
                                    except:
                                        continue
        except Exception as e:
            self.log(f"Error checking robots.txt: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_dns_zone_transfer(self):
        self.log("Attempting DNS zone transfer...")
        ips = set()
        
        try:
            # Get nameservers
            result = self.dns_query('', 'NS')
            if result:
                _, nameservers = result
                for ns in nameservers:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [socket.gethostbyname(ns)]
                        
                        try:
                            answers = resolver.query(self.domain, 'AXFR')
                            for rdata in answers:
                                if rdata.rdtype == dns.rdatatype.A:
                                    ips.add(rdata.address)
                                    self.log(f"Found via AXFR: {rdata.address}", "success")
                        except dns.resolver.NoAnswer:
                            continue
                        except dns.exception.DNSException:
                            continue
                    except:
                        continue
        except Exception as e:
            self.log(f"Error attempting zone transfer: {str(e)}", "error")
        
        return list(ips) if ips else None
    
    def _check_common_vhosts(self):
        self.log("Checking common vhosts...")
        ips = set()
        
        common_vhosts = [
            'admin', 'beta', 'dev', 'development', 'internal', 'private',
            'secure', 'staging', 'test', 'vpn', 'web', 'web01', 'web1',
            'web02', 'web2', 'www1', 'www2', 'origin', 'backend', 'api',
            'app', 'apps', 'dashboard', 'console', 'control', 'manager'
        ]
        
        for vhost in common_vhosts:
            target = f"{vhost}.{self.domain}"
            try:
                result = self.dns_query(vhost)
                if result:
                    _, addresses = result
                    for ip in addresses:
                        if not self.is_cloudflare_ip(ip):
                            ips.add(ip)
                            self.log(f"Found via vhost {target}: {ip}", "success")
            except:
                continue
        
        return list(ips) if ips else None
    
    def _check_historical_ip_data(self):
        self.log("Checking historical IP data...")
        ips = set()
        
        try:
            url = f"https://securitytrails.com/domain/{self.domain}/history/a"
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'application/json'
            }
            response = self.session.get(url, headers=headers, timeout=TIMEOUT*2)
            
            if response.status_code == 200:
                data = response.json()
                for record in data.get('records', []):
                    for value in record.get('values', []):
                        ip = value.get('ip')
                        if ip:
                            ips.add(ip)
        except Exception as e:
            self.log(f"Error checking historical IP data: {str(e)}", "error")
        
        return list(ips) if ips else None

def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain and Origin IP Discovery Tool with WAF Bypass")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS, help="Number of threads for brute force")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    if not args.domain:
        parser.print_help()
        sys.exit(1)
    
    finder = AdvancedSubdomainFinder(args.domain, args.output, args.threads, args.verbose)
    
    print(f"[*] Starting advanced reconnaissance on {args.domain}")
    print(f"[*] Using {args.threads} threads for scanning\n")
    
    # Perform comprehensive subdomain enumeration
    finder.brute_force_subdomains()
    finder.check_certificate_transparency()
    finder.check_dns_records()
    
    # Check if main domain is behind WAF
    print("\n[*] Checking if main domain is behind WAF...")
    is_protected = finder.check_security_headers(f"https://{args.domain}")
    if is_protected:
        print("[!] Site appears to be protected by WAF/CDN")
    else:
        print("[+] Site does not appear to be protected by WAF/CDN")
    
    # Attempt to find origin IP if behind protection
    if is_protected:
        print("\n[*] Attempting to find origin IP using multiple techniques...")
        origin_ips = finder.find_origin_ip()
        
        if origin_ips:
            print("\n[+] Potential origin IPs found:")
            for ip in sorted(origin_ips):
                print(f"  - {ip}")
        else:
            print("[-] No origin IPs found")
    
    # Show all found subdomains
    print(f"\n[+] Found {len(finder.found_subdomains)} subdomains:")
    for sub in sorted(finder.found_subdomains):
        print(f"  - {sub}")
    
    # Show all found IPs
    print(f"\n[+] Found {len(finder.found_ips)} unique IP addresses:")
    for ip in sorted(finder.found_ips):
        print(f"  - {ip}")
    
    if args.output:
        finder.save_results()
    
    print("\n[+] Advanced scan completed successfully")

if __name__ == "__main__":
    main()
