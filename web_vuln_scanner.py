#!/usr/bin/env python3
# web_vuln_scanner.py - Basic web application vulnerability scanner
# Usage: python3 web_vuln_scanner.py <url> [options]

import argparse
import concurrent.futures
import json
import os
import random
import re
import ssl
import sys
import time
import socket
import urllib.parse
from collections import defaultdict
from datetime import datetime

# Try to import optional dependencies
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Error: requests module not installed. Install with: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    print("[!] Warning: BeautifulSoup not installed. Some features will be limited.")
    print("[!] Install with: pip install beautifulsoup4")
    BS4_AVAILABLE = False

# Global variables
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "';alert('XSS');//",
    "\"><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>prompt('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<h1 onclick=alert('XSS')>Click me</h1>"
]

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' UNION SELECT 1,2,3--+",
    "1' UNION SELECT NULL,NULL,NULL--+",
    "' OR sleep(5) #",
    "' AND sleep(5) AND '1'='1",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/hosts",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../etc/passwd%00",
    "../../../../etc/passwd%00",
    "/etc/passwd",
    "../Windows/win.ini",
    "../../Windows/win.ini",
    "../../../Windows/win.ini",
    "../../../../Windows/win.ini",
    "C:/Windows/win.ini",
    "C:\\Windows\\win.ini"
]

COMMON_DIRECTORIES = [
    "admin", "administrator", "backup", "backups", "config", "dashboard", 
    "db", "debug", "default", "dev", "files", "home", "images", "img", 
    "js", "log", "logs", "login", "static", "test", "tmp", "upload", 
    "uploads", "wp-admin", "wp-content", "wp-includes", ".git", ".svn", 
    "api", "admin.php", "login.php", "wp-login.php", "robots.txt", 
    "sitemap.xml", "phpinfo.php", "info.php", "server-status", "server-info",
    ".env", ".htaccess", "backup.zip", "db.sql", "database.sql", "1.sql",
    "dump.sql", "backup.sql", "config.php", "config.inc.php", "configuration.php"
]

HEADERS_TO_CHECK = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy",
    "Strict-Transport-Security", "X-Content-Type-Options"
]

class WebVulnScanner:
    def __init__(self, target_url, options):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else 'http://' + target_url
        self.options = options
        self.base_url = self.get_base_url()
        self.session = requests.Session()
        self.session.verify = not options.insecure
        self.session.timeout = options.timeout
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        if options.cookies:
            self.set_cookies(options.cookies)
        
        self.visited_urls = set()
        self.forms = []
        self.findings = defaultdict(list)
        self.start_time = datetime.now()
        
        # Create output directory if specified
        if options.output_dir:
            os.makedirs(options.output_dir, exist_ok=True)
    
    def get_base_url(self):
        """Extract base URL from target URL."""
        parsed = urllib.parse.urlparse(self.target_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def set_cookies(self, cookies_str):
        """Set session cookies from string."""
        cookies = {}
        try:
            for cookie in cookies_str.split(';'):
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
            self.session.cookies.update(cookies)
        except Exception as e:
            print(f"[!] Error parsing cookies: {e}")
    
    def make_request(self, url, method="GET", data=None, allow_redirects=True):
        """Make HTTP request with error handling."""
        try:
            full_url = url if url.startswith(('http://', 'https://')) else urllib.parse.urljoin(self.base_url, url)
            
            if method == "GET":
                response = self.session.get(
                    full_url, 
                    allow_redirects=allow_redirects
                )
            elif method == "POST":
                response = self.session.post(
                    full_url, 
                    data=data, 
                    allow_redirects=allow_redirects
                )
            else:
                return None
            
            return response
        except requests.exceptions.Timeout:
            if self.options.verbose:
                print(f"[!] Timeout accessing: {url}")
            return None
        except requests.exceptions.ConnectionError:
            if self.options.verbose:
                print(f"[!] Connection error accessing: {url}")
            return None
        except requests.exceptions.RequestException as e:
            if self.options.verbose:
                print(f"[!] Error accessing {url}: {e}")
            return None
    
    def extract_links(self, response):
        """Extract links from response."""
        links = set()
        
        if not response or not response.text:
            return links
        
        # Use BeautifulSoup if available for better parsing
        if BS4_AVAILABLE:
            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                links.add(link)
        else:
            # Simple regex-based link extraction
            href_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
            for match in href_pattern.finditer(response.text):
                link = match.group(1)
                links.add(link)
        
        # Normalize links
        normalized_links = set()
        for link in links:
            # Skip empty links and javascript
            if not link or link.startswith('javascript:') or link == '#':
                continue
            
            # Handle relative URLs
            if not link.startswith(('http://', 'https://')):
                link = urllib.parse.urljoin(response.url, link)
            
            # Only include links from the same domain if not scanning externally
            if not self.options.external and not link.startswith(self.base_url):
                continue
            
            normalized_links.add(link)
        
        return normalized_links
    
    def extract_forms(self, response):
        """Extract forms from response."""
        forms = []
        
        if not response or not response.text:
            return forms
        
        # Use BeautifulSoup if available for better parsing
        if BS4_AVAILABLE:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', '')
                    input_name = input_tag.get('name', '')
                    
                    if input_name and input_type != 'submit':
                        form_info['inputs'].append({
                            'name': input_name,
                            'type': input_type
                        })
                
                # Resolve relative action URL
                if form_info['action'] and not form_info['action'].startswith(('http://', 'https://')):
                    form_info['action'] = urllib.parse.urljoin(response.url, form_info['action'])
                
                forms.append(form_info)
        else:
            # Simple regex-based form extraction
            form_pattern = re.compile(r'<form.*?action=["\'](.*?)["\'].*?method=["\'](.*?)["\'].*?>(.*?)</form>', re.IGNORECASE | re.DOTALL)
            input_pattern = re.compile(r'<input.*?name=["\'](.*?)["\'].*?type=["\'](.*?)["\'].*?>', re.IGNORECASE)
            
            for form_match in form_pattern.finditer(response.text):
                action = form_match.group(1) or ''
                method = form_match.group(2).upper() or 'GET'
                form_content = form_match.group(3)
                
                form_info = {
                    'action': action,
                    'method': method,
                    'inputs': []
                }
                
                for input_match in input_pattern.finditer(form_content):
                    input_name = input_match.group(1)
                    input_type = input_match.group(2)
                    
                    if input_name and input_type != 'submit':
                        form_info['inputs'].append({
                            'name': input_name,
                            'type': input_type
                        })
                
                # Resolve relative action URL
                if form_info['action'] and not form_info['action'].startswith(('http://', 'https://')):
                    form_info['action'] = urllib.parse.urljoin(response.url, form_info['action'])
                
                forms.append(form_info)
        
        return forms
    
    def crawl(self):
        """Crawl the target website to discover pages and forms."""
        print(f"[*] Starting crawl of {self.target_url}")
        to_visit = [self.target_url]
        
        while to_visit and len(self.visited_urls) < self.options.max_urls:
            current_url = to_visit.pop(0)
            
            if current_url in self.visited_urls:
                continue
            
            print(f"[*] Crawling: {current_url}")
            self.visited_urls.add(current_url)
            
            response = self.make_request(current_url)
            if not response:
                continue
            
            # Extract forms
            page_forms = self.extract_forms(response)
            for form in page_forms:
                if form not in self.forms:
                    self.forms.append(form)
            
            # Extract and queue links if depth allows
            if len(self.visited_urls) < self.options.max_urls:
                links = self.extract_links(response)
                for link in links:
                    if link not in self.visited_urls and link not in to_visit:
                        to_visit.append(link)
        
        print(f"[*] Crawl complete. Discovered {len(self.visited_urls)} URLs and {len(self.forms)} forms")
    
    def scan_headers(self, url=None):
        """Check for security headers."""
        target = url or self.target_url
        print(f"[*] Checking security headers for {target}")
        
        response = self.make_request(target)
        if not response:
            return
        
        missing_headers = []
        insecure_headers = []
        
        # Check for missing security headers
        if 'X-Frame-Options' not in response.headers:
            missing_headers.append('X-Frame-Options')
        
        if 'X-XSS-Protection' not in response.headers:
            missing_headers.append('X-XSS-Protection')
        elif response.headers.get('X-XSS-Protection') == '0':
            insecure_headers.append('X-XSS-Protection: 0 (disabled)')
        
        if 'Content-Security-Policy' not in response.headers:
            missing_headers.append('Content-Security-Policy')
        
        if 'X-Content-Type-Options' not in response.headers:
            missing_headers.append('X-Content-Type-Options')
        
        if 'Strict-Transport-Security' not in response.headers and target.startswith('https://'):
            missing_headers.append('Strict-Transport-Security')
        
        # Check for information disclosure
        if 'Server' in response.headers:
            server = response.headers['Server']
            self.findings['information_disclosure'].append({
                'url': target,
                'type': 'Server header',
                'value': server
            })
        
        if 'X-Powered-By' in response.headers:
            powered_by = response.headers['X-Powered-By']
            self.findings['information_disclosure'].append({
                'url': target,
                'type': 'X-Powered-By header',
                'value': powered_by
            })
        
        # Record findings
        if missing_headers:
            self.findings['missing_headers'].append({
                'url': target,
                'missing': missing_headers
            })
        
        if insecure_headers:
            self.findings['insecure_headers'].append({
                'url': target,
                'insecure': insecure_headers
            })
    
    def scan_ssl_tls(self):
        """Check for SSL/TLS vulnerabilities."""
        if not self.target_url.startswith('https://'):
            print("[*] Target is not using HTTPS, skipping SSL/TLS checks")
            return
        
        print(f"[*] Checking SSL/TLS configuration for {self.target_url}")
        parsed = urllib.parse.urlparse(self.target_url)
        hostname = parsed.netloc
        port = parsed.port or 443
        
        try:
            # Try to connect with SSLv3 (vulnerable)
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options &= ~ssl.OP_NO_SSLv3
            
            with socket.create_connection((hostname, port)) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        self.findings['ssl_vulnerabilities'].append({
                            'url': self.target_url,
                            'type': 'SSLv3 Supported',
                            'details': 'Server supports SSLv3, which is vulnerable to the POODLE attack'
                        })
                except ssl.SSLError:
                    # SSLv3 not supported (good)
                    pass
            
            # Check for TLS 1.0/1.1 (outdated)
            for protocol, name in [(ssl.PROTOCOL_TLSv1, 'TLSv1.0'), (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1')]:
                context = ssl.SSLContext(protocol)
                
                with socket.create_connection((hostname, port)) as sock:
                    try:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            self.findings['ssl_vulnerabilities'].append({
                                'url': self.target_url,
                                'type': f'{name} Supported',
                                'details': f'Server supports {name}, which is outdated and should be disabled'
                            })
                    except ssl.SSLError:
                        # Protocol not supported (good)
                        pass
            
            # Check cipher suites (basic check)
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher and cipher[0] and ('NULL' in cipher[0] or 'RC4' in cipher[0] or 'MD5' in cipher[0]):
                        self.findings['ssl_vulnerabilities'].append({
                            'url': self.target_url,
                            'type': 'Weak Cipher Suite',
                            'details': f'Server uses weak cipher: {cipher[0]}'
                        })
        
        except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            print(f"[!] Error checking SSL/TLS: {e}")
    
    def test_xss(self, url, param_name, method="GET"):
        """Test for XSS vulnerabilities in a parameter."""
        for payload in XSS_PAYLOADS:
            test_url = url
            data = None
            
            if method == "GET":
                if '?' in url:
                    test_url = f"{url}&{param_name}={urllib.parse.quote(payload)}"
                else:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
            else:  # POST
                data = {param_name: payload}
            
            response = self.make_request(test_url, method=method, data=data)
            if not response:
                continue
            
            # Check if the payload is reflected in the response
            if payload in response.text:
                self.findings['xss_vulnerabilities'].append({
                    'url': url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': f"Payload was reflected in the response"
                })
                return True  # Found XSS, no need to try other payloads
        
        return False
    
    def test_sqli(self, url, param_name, method="GET"):
        """Test for SQL injection vulnerabilities in a parameter."""
        # First make a normal request to get baseline response
        baseline_url = url
        baseline_data = None
        
        if method == "GET":
            if '?' in url:
                baseline_url = f"{url}&{param_name}=normal"
            else:
                baseline_url = f"{url}?{param_name}=normal"
        else:  # POST
            baseline_data = {param_name: "normal"}
        
        baseline_response = self.make_request(baseline_url, method=method, data=baseline_data)
        if not baseline_response:
            return False
        
        baseline_length = len(baseline_response.text)
        baseline_status = baseline_response.status_code
        
        # Test SQL injection payloads
        for payload in SQL_PAYLOADS:
            test_url = url
            data = None
            
            if method == "GET":
                if '?' in url:
                    test_url = f"{url}&{param_name}={urllib.parse.quote(payload)}"
                else:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
            else:  # POST
                data = {param_name: payload}
            
            start_time = time.time()
            response = self.make_request(test_url, method=method, data=data)
            elapsed_time = time.time() - start_time
            
            if not response:
                continue
            
            # Look for SQL error messages
            sql_errors = [
                "sql syntax", "syntax error", "unclosed quotation", "unterminated string",
                "mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows",
                "mysql_fetch_row", "mysql_fetch_object", "mysql_numrows",
                "sql server", "odbc driver", "ora-", "oracle error", "pg_query",
                "database error", "data source error", "db2 error", "sql command",
                "mysqli_", "mariadb", "postgres", "sqlite"
            ]
            
            for error in sql_errors:
                if error in response.text.lower():
                    self.findings['sqli_vulnerabilities'].append({
                        'url': url,
                        'parameter': param_name,
                        'method': method,
                        'payload': payload,
                        'evidence': f"SQL error message detected: '{error}'"
                    })
                    return True
            
            # Look for blind SQL injection indicators
            if 'sleep' in payload.lower() and elapsed_time > self.options.timeout * 0.8:
                self.findings['sqli_vulnerabilities'].append({
                    'url': url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': f"Time-based SQL injection detected (response time: {elapsed_time:.2f}s)"
                })
                return True
            
            # Look for significant response differences
            response_difference = abs(len(response.text) - baseline_length) / baseline_length
            if response_difference > 0.3 and baseline_status == response.status_code:
                self.findings['sqli_vulnerabilities'].append({
                    'url': url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': f"Response length changed significantly ({response_difference:.2%} difference)"
                })
                return True
        
        return False
    
    def test_lfi(self, url, param_name, method="GET"):
        """Test for Local File Inclusion vulnerabilities in a parameter."""
        for payload in LFI_PAYLOADS:
            test_url = url
            data = None
            
            if method == "GET":
                if '?' in url:
                    test_url = f"{url}&{param_name}={urllib.parse.quote(payload)}"
                else:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
            else:  # POST
                data = {param_name: payload}
            
            response = self.make_request(test_url, method=method, data=data)
            if not response:
                continue
            
            # Look for evidence of successful LFI
            lfi_indicators = [
                "root:x:", "daemon:x:", "bin:x:", "sys:x:",  # Linux /etc/passwd
                "[drivers]", "[filesystem]", "[fonts]",  # Windows win.ini
                "for 16-bit app support", "MSDos", "Windows Registry"  # Windows files content
            ]
            
            for indicator in lfi_indicators:
                if indicator in response.text:
                    self.findings['lfi_vulnerabilities'].append({
                        'url': url,
                        'parameter': param_name,
                        'method': method,
                        'payload': payload,
                        'evidence': f"LFI indicator found: '{indicator}'"
                    })
                    return True
        
        return False
    
    def scan_url_parameters(self, url):
        """Scan URL parameters for vulnerabilities."""
        print(f"[*] Checking URL parameters in: {url}")
        
        # Parse URL and extract parameters
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        if not parsed_url.query:
            return
        
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Test each parameter
        for param_name in query_params.keys():
            if self.options.xss:
                if self.test_xss(base_url, param_name, "GET"):
                    print(f"[+] XSS vulnerability found in parameter: {param_name}")
            
            if self.options.sqli:
                if self.test_sqli(base_url, param_name, "GET"):
                    print(f"[+] SQL Injection vulnerability found in parameter: {param_name}")
            
            if self.options.lfi:
                if self.test_lfi(base_url, param_name, "GET"):
                    print(f"[+] Local File Inclusion vulnerability found in parameter: {param_name}")
    
    def scan_forms(self, form):
        """Scan form inputs for vulnerabilities."""
        if not form.get('inputs'):
            return
        
        action_url = form.get('action', '')
        method = form.get('method', 'GET')
        
        print(f"[*] Checking form: {action_url} (Method: {method})")
        
        for input_field in form['inputs']:
            input_name = input_field.get('name', '')
            if not input_name:
                continue
            
            if self.options.xss:
                if self.test_xss(action_url, input_name, method):
                    print(f"[+] XSS vulnerability found in form field: {input_name}")
            
            if self.options.sqli:
                if self.test_sqli(action_url, input_name, method):
                    print(f"[+] SQL Injection vulnerability found in form field: {input_name}")
            
            if self.options.lfi:
                if self.test_lfi(action_url, input_name, method):
                    print(f"[+] Local File Inclusion vulnerability found in form field: {input_name}")
    
    def directory_scan(self):
        """Scan for common directories and files."""
        print(f"[*] Scanning for common directories and files")
        
        found_resources = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.options.threads) as executor:
            future_to_path = {}
            
            for path in COMMON_DIRECTORIES:
                test_url = urllib.parse.urljoin(self.base_url, path)
                future = executor.submit(self.make_request, test_url)
                future_to_path[future] = path
            
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    response = future.result()
                    if response and response.status_code < 404:
                        found_url = urllib.parse.urljoin(self.base_url, path)
                        found_resources.append({
                            'url': found_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        })
                        print(f"[+] Found: {found_url} (Status: {response.status_code})")
                except Exception as e:
                    if self.options.verbose:
                        print(f"[!] Error checking {path}: {e}")
        
        if found_resources:
            self.findings['directory_scan'] = found_resources
    
    def generate_report(self):
        """Generate a report of findings."""
        print("\n[*] Generating vulnerability report...")
        
        total_findings = sum(len(findings) for findings in self.findings.values())
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        report = {
            'scan_info': {
                'target': self.target_url,
                'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': f"{duration:.2f} seconds",
                'urls_crawled': len(self.visited_urls),
                'forms_analyzed': len(self.forms)
            },
            'summary': {
                'total_findings': total_findings,
                'missing_headers': len(self.findings.get('missing_headers', [])),
                'information_disclosure': len(self.findings.get('information_disclosure', [])),
                'ssl_vulnerabilities': len(self.findings.get('ssl_vulnerabilities', [])),
                'xss_vulnerabilities': len(self.findings.get('xss_vulnerabilities', [])),
                'sqli_vulnerabilities': len(self.findings.get('sqli_vulnerabilities', [])),
                'lfi_vulnerabilities': len(self.findings.get('lfi_vulnerabilities', [])),
                'resources_found': len(self.findings.get('directory_scan', []))
            },
            'findings': self.findings
        }
        
        # Write report to file if output directory is specified
        if self.options.output_dir:
            report_file = os.path.join(self.options.output_dir, f"scan_report_{end_time.strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"[+] Report saved to: {report_file}")
        
        # Print summary
        print("\n=== Vulnerability Scan Summary ===")
        print(f"Target: {self.target_url}")
        print(f"Scan duration: {duration:.2f} seconds")
        print(f"URLs crawled: {len(self.visited_urls)}")
        print(f"Forms analyzed: {len(self.forms)}")
        print(f"Total findings: {total_findings}")
        print("\nFindings breakdown:")
        print(f"- Missing security headers: {report['summary']['missing_headers']}")
        print(f"- Information disclosure: {report['summary']['information_disclosure']}")
        print(f"- SSL/TLS vulnerabilities: {report['summary']['ssl_vulnerabilities']}")
        print(f"- XSS vulnerabilities: {report['summary']['xss_vulnerabilities']}")
        print(f"- SQL Injection vulnerabilities: {report['summary']['sqli_vulnerabilities']}")
        print(f"- LFI vulnerabilities: {report['summary']['lfi_vulnerabilities']}")
        print(f"- Resources discovered: {report['summary']['resources_found']}")
        
        if total_findings > 0:
            print("\nHighlights:")
            
            # Print XSS vulnerabilities
            if self.findings.get('xss_vulnerabilities'):
                print("\nXSS Vulnerabilities:")
                for i, vuln in enumerate(self.findings['xss_vulnerabilities'][:3], 1):
                    print(f"  {i}. URL: {vuln['url']}, Parameter: {vuln['parameter']}")
                if len(self.findings['xss_vulnerabilities']) > 3:
                    print(f"  ... and {len(self.findings['xss_vulnerabilities']) - 3} more")
            
            # Print SQL Injection vulnerabilities
            if self.findings.get('sqli_vulnerabilities'):
                print("\nSQL Injection Vulnerabilities:")
                for i, vuln in enumerate(self.findings['sqli_vulnerabilities'][:3], 1):
                    print(f"  {i}. URL: {vuln['url']}, Parameter: {vuln['parameter']}")
                if len(self.findings['sqli_vulnerabilities']) > 3:
                    print(f"  ... and {len(self.findings['sqli_vulnerabilities']) - 3} more")
            
            # Print LFI vulnerabilities
            if self.findings.get('lfi_vulnerabilities'):
                print("\nLocal File Inclusion Vulnerabilities:")
                for i, vuln in enumerate(self.findings['lfi_vulnerabilities'][:3], 1):
                    print(f"  {i}. URL: {vuln['url']}, Parameter: {vuln['parameter']}")
                if len(self.findings['lfi_vulnerabilities']) > 3:
                    print(f"  ... and {len(self.findings['lfi_vulnerabilities']) - 3} more")
        
        return report
    
    def run(self):
        """Run the web vulnerability scanner."""
        print(f"Starting Web Vulnerability Scanner on {self.target_url}")
        print(f"Options: {vars(self.options)}")
        
        # Initial request to check if the target is reachable
        initial_response = self.make_request(self.target_url)
        if not initial_response:
            print(f"[!] Unable to connect to {self.target_url}")
            return False
        
        # Crawl the site if enabled
        if self.options.crawl:
            self.crawl()
        else:
            self.visited_urls.add(self.target_url)
            # Extract forms from the initial page
            page_forms = self.extract_forms(initial_response)
            for form in page_forms:
                if form not in self.forms:
                    self.forms.append(form)
        
        # Check security headers
        if self.options.headers:
            self.scan_headers()
        
        # Check SSL/TLS if applicable
        if self.options.ssl and self.target_url.startswith('https://'):
            self.scan_ssl_tls()
        
        # Scan for directories and files
        if self.options.dirb:
            self.directory_scan()
        
        # Scan URL parameters
        if self.options.xss or self.options.sqli or self.options.lfi:
            print("[*] Scanning URL parameters for vulnerabilities")
            for url in self.visited_urls:
                self.scan_url_parameters(url)
        
        # Scan forms
        if self.options.forms and self.forms:
            print("[*] Scanning forms for vulnerabilities")
            for form in self.forms:
                self.scan_forms(form)
        
        # Generate report
        self.generate_report()
        
        print("\n[*] Scan completed")
        return True

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    
    # Target specification
    parser.add_argument("url", help="Target URL to scan")
    
    # Crawling options
    parser.add_argument("--crawl", action="store_true", help="Enable crawling")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum number of URLs to crawl")
    parser.add_argument("--external", action="store_true", help="Allow crawling external domains")
    
    # Scan options
    parser.add_argument("--headers", action="store_true", help="Check security headers")
    parser.add_argument("--ssl", action="store_true", help="Check SSL/TLS configuration")
    parser.add_argument("--dirb", action="store_true", help="Scan for common directories and files")
    parser.add_argument("--forms", action="store_true", help="Scan forms for vulnerabilities")
    
    # Vulnerability checks
    parser.add_argument("--xss", action="store_true", help="Check for XSS vulnerabilities")
    parser.add_argument("--sqli", action="store_true", help="Check for SQL Injection vulnerabilities")
    parser.add_argument("--lfi", action="store_true", help="Check for Local File Inclusion vulnerabilities")
    
    # General options
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for scanning")
    parser.add_argument("--output-dir", help="Directory to save results")
    parser.add_argument("--cookies", help="Cookies to use in requests (format: name=value;name2=value2)")
    parser.add_argument("--insecure", action="store_true", help="Ignore SSL certificate errors")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--all", action="store_true", help="Enable all scan options")
    
    args = parser.parse_args()
    
    # If --all is specified, enable all scan options
    if args.all:
        args.crawl = True
        args.headers = True
        args.ssl = True
        args.dirb = True
        args.forms = True
        args.xss = True
        args.sqli = True
        args.lfi = True
    
    # Create and run the scanner
    scanner = WebVulnScanner(args.url, args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.generate_report()
        sys.exit(1)

if __name__ == "__main__":
    print("""
 __        __   _     __     __    _       ____                                 
 \ \      / /__| |__ / _|_  / /   | |     / ___|  ___ __ _ _ __  _ __   ___ _ __ 
  \ \ /\ / / _ \ '_ \| |_ \/ /    | |     \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \ V  V /  __/ |_) |  _|/ /     | |___   ___) | (_| (_| | | | | | | |  __/ |   
    \_/\_/ \___|_.__/|_| /_/      |_____| |____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                
  Web Vulnerability Scanner - For authorized security testing only
""")
    main()
