# Chapter 5: Web Application Vulnerability Scanning

Web applications represent one of the most common attack vectors for modern organizations. As a red teamer, you need a solid understanding of tools that can identify vulnerabilities in web applications quickly and effectively. This chapter covers essential web application scanning tools available in Kali Linux and Parrot OS.

## OWASP ZAP (Zed Attack Proxy)

The OWASP Zed Attack Proxy (ZAP) is an open-source web application security scanner maintained by the Open Web Application Security Project (OWASP). ZAP provides a comprehensive set of tools for finding vulnerabilities in web applications during penetration testing.

### Key Features

- **Intercepting Proxy**: Monitor and manipulate traffic between your browser and the target application
- **Automated Scanner**: Discover vulnerabilities automatically
- **Spider**: Crawl web applications to identify content and functionality
- **Fuzzer**: Test for injection vulnerabilities by sending unexpected data
- **REST API**: Integrate ZAP with CI/CD pipelines for continuous security testing
- **Scriptable**: Extend functionality using JavaScript, Python, Ruby or Groovy

### Active vs. Passive Scanning

ZAP offers two primary scanning modes:

**Passive Scanning**: Analyzes HTTP messages (requests and responses) without modifying them or sending additional requests. This is non-intrusive but can still identify:
- Information leakage issues
- Configuration problems
- Client-side code issues (Cross-Site Scripting)
- Cookie security issues

**Active Scanning**: Actively probes the application by sending additional requests to test for vulnerabilities. Can identify:
- SQL injection
- Cross-site scripting (XSS)
- Directory traversal
- Command injection
- Server misconfigurations

### Custom Scan Policies

ZAP allows you to create custom scan policies to target specific types of vulnerabilities or to adjust the thoroughness of scanning. This is particularly useful in red team engagements where time might be limited or when targeting specific vulnerabilities.

To create a custom scan policy:

1. In ZAP, go to Analysis → Scan Policy Manager
2. Click "Add" to create a new policy
3. Name your policy and select a strength (Default, Low, Medium, High)
4. Adjust individual test rules by enabling/disabling them or changing their thresholds

### Example: Detecting OWASP Top 10 Vulnerabilities

Here's a walkthrough of using ZAP to identify an SQL injection vulnerability (part of OWASP Top 10):

1. Start ZAP and set it as your browser proxy (typically 127.0.0.1:8080)
2. Navigate to your target application in the browser
3. Explore the application, focusing on forms, search fields, and dynamic content
4. In ZAP, right-click on your target in the Sites tree and select "Attack" → "Active Scan"
5. Configure the scan parameters, emphasizing SQL Injection tests
6. Start the scan and analyze the results

Output example for an SQL Injection vulnerability:

```
ALERT: SQL Injection - Found on URL: https://target-app.com/search.php
Parameter: id
Attack: 1' OR '1'='1
Evidence: You have an error in your SQL syntax; check the manual that corresponds 
to your MySQL server version for the right syntax to use near ''1' OR '1'='1'' at line 1
Risk: High
Confidence: Medium
CWE ID: 89
Solution: Parameterize queries, use prepared statements, validate inputs rigorously
```

After identifying vulnerabilities, ZAP generates comprehensive reports in various formats including HTML, XML, JSON, and PDF, which are essential for documenting findings during red team assessments.

### Advanced ZAP Usage for Red Teams

For red team operations, consider these advanced ZAP techniques:

1. **Context-aware scanning**: Create contexts to define the scope of your testing and include authentication details.

2. **Script Console**: Automate repetitive tasks and extend ZAP's functionality:

```javascript
// Script to extract all hidden form fields from responses
var extHiddenFields = {
  processHttpResponseReceive: function(msg) {
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString();
    var hiddenRegex = /<input[^>]+type=['"]hidden['"][^>]*>/g;
    var hiddenFields = body.match(hiddenRegex);
    
    if (hiddenFields) {
      print('Hidden fields found in: ' + url);
      for (var i=0; i < hiddenFields.length; i++) {
        print('\t' + hiddenFields[i]);
      }
    }
    return true;
  }
};
```

3. **Websocket testing**: Target modern applications that use WebSockets for real-time communication.

4. **Parameter pollution**: Test for HTTP Parameter Pollution vulnerabilities, which can bypass input filters.

## Skipfish 

Skipfish is a high-performance, active web application security reconnaissance tool. It's designed for speed, generating comprehensive, interactive reports for analysis and optimization of web application assessments.

### Key Features

- **High-speed crawler**: Can process hundreds of requests per second
- **Active security checks**: Probes for vulnerabilities with minimal false positives
- **Recursive directory brute-force**: Discovers hidden content
- **Form submission engine**: Automatically completes and submits forms
- **Interactive reporting interface**: Generates browsable HTML reports

### Configuration for Different Application Types

Skipfish can be tailored for different web application types:

**For PHP Applications**:
```bash
skipfish -o output_dir -I php,asp,txt -X js,css,gif,jpg,png -S dictionaries/minimal.wl -u https://target-php-app.com
```

**For Java Applications**:
```bash
skipfish -o output_dir -I jsp,do,action -X js,css,gif,jpg,png -S dictionaries/complete.wl -u https://target-java-app.com
```

**For .NET Applications**:
```bash
skipfish -o output_dir -I aspx,ashx,asmx -X js,css,gif,jpg,png -S dictionaries/medium.wl -u https://target-dotnet-app.com
```

### Example: High-speed Application Mapping

This example demonstrates how to perform a comprehensive scan of a target web application, focusing on mapping its structure while identifying potential security issues:

```bash
skipfish -o output_dir \
         -S /usr/share/skipfish/dictionaries/complete.wl \
         -W /usr/share/skipfish/dictionaries/high-risk-extensions.wl \
         -M 10 \
         -l 2 \
         -k 200 \
         -p 127.0.0.1:8080:1 \
         -A Mozilla/5.0 \
         -X jpg,gif,png,css,js \
         -u https://target-application.com
```

Parameter breakdown:
- `-o output_dir`: Directory for storing results
- `-S complete.wl`: Dictionary file for brute-forcing
- `-W high-risk-extensions.wl`: Extensions considered high-risk
- `-M 10`: Maximum crawl depth
- `-l 2`: Request parallelism
- `-k 200`: Limit on the maximum number of requests
- `-p 127.0.0.1:8080:1`: Route through local proxy (useful for capturing in Burp/ZAP)
- `-A Mozilla/5.0`: Custom user agent
- `-X jpg,gif,png,css,js`: Skip these file extensions
- `-u https://target-application.com`: Target URL

After completion, navigate to the output directory and open `index.html` to view an interactive report of all discovered resources and vulnerabilities.

### Red Team Tips for Skipfish

- Combine with other tools (like Nikto or OWASP ZAP) for comprehensive coverage
- Use the `-p` option to route through a proxy for traffic analysis
- Focus on server-side logic with `-X` to exclude static content
- Create custom wordlists tailored to the target application's technology stack
- Monitor resource usage with `-d` for request throttling to avoid detection

## Wapiti

Wapiti is a web application vulnerability scanner that performs "black-box" scanning, meaning it doesn't review the source code but rather executes attacks and analyzes responses to identify vulnerabilities.

### Key Features

- **Multiple vulnerability detection**: SQL Injection, XSS, XXE, SSRF, CRLF, and more
- **Form crawling**: Automatically finds and tests forms
- **Cookie and authentication support**: Can authenticate with the target application
- **Custom payloads**: Define your own attack patterns
- **Reporting**: Generates reports in various formats

### Module Configuration

Wapiti's modular architecture allows you to enable or disable specific vulnerability checks:

| Module | Description |
|--------|-------------|
| backup | Searches for backup files |
| blindsql | Detects blind SQL injection vulnerabilities |
| buster | Directory and file enumeration |
| cookieflags | Checks cookie security flags |
| crlf | Detects CRLF injection points |
| csrf | Checks for Cross-Site Request Forgery |
| exec | Command execution vulnerabilities |
| file | Path traversal and file inclusion |
| htaccess | Tests for .htaccess bypassing |
| methods | HTTP method testing |
| nikto | Integrates Nikto database checks |
| permanentxss | Stored XSS vulnerabilities |
| redirect | Open redirect vulnerabilities |
| shellshock | Tests for Shellshock vulnerability |
| sql | SQL injection vulnerabilities |
| ssrf | Server-Side Request Forgery |
| xss | Reflected Cross-Site Scripting |
| xxe | XML External Entity attacks |

### Example: Identifying Injection Flaws

The following command will scan a target application for SQL injection and XSS vulnerabilities, while authenticating to the application:

```bash
wapiti -u "https://target-app.com/" \
       -m "sql,xss" \
       --auth-method="post" \
       --auth-url="https://target-app.com/login.php" \
       --auth-data="username=admin&password=password" \
       --color \
       -v 2 \
       -f html \
       -o wapiti-report
```

Sample output for an identified SQL injection vulnerability:

```
---
SQL Injection (SQLI) in https://target-app.com/product.php
Evil request:
    GET /product.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1
    Host: target-app.com
    [...]
Vulnerable parameter: id
---
```

### Recommended Workflow for Red Teams

1. **Initial reconnaissance**:
   ```bash
   wapiti -u "https://target-app.com/" -m "buster"
   ```

2. **Follow with targeted scanning**:
   ```bash
   wapiti -u "https://target-app.com/" \
          -m "sql,xss,file,exec,redirect,ssrf" \
          --scope "folder" \
          -d 3
   ```

3. **Generate a comprehensive report**:
   ```bash
   wapiti -u "https://target-app.com/" \
          -m "all" \
          --scope "domain" \
          -f html,json,txt \
          -o wapiti-full-report
   ```

## Nuclei

Nuclei is a fast, template-based vulnerability scanner designed for extensive scanning with a vast library of templates. It's particularly effective for detecting known CVEs, misconfigurations, and security issues.

### Key Features

- **Template-based scanning**: Standardized approach to vulnerability detection
- **Extensive template library**: Thousands of ready-to-use templates
- **Multi-protocol support**: HTTP, DNS, TCP, SSL, etc.
- **Highly configurable**: Customize scanning behavior
- **Fast execution**: Optimized for scanning large targets
- **Low false positives**: Templates are typically well-tested

### Creating Custom Templates

Nuclei templates are YAML files that define the scanning logic. Creating custom templates allows you to detect specific vulnerabilities or misconfigurations that are relevant to your red team engagement.

Here's a basic template structure for detecting a custom vulnerability:

```yaml
# wordpress-debug-log.yaml - Detects exposed WordPress debug logs
id: wordpress-debug-log

info:
  name: WordPress Debug Log Detection
  author: RedTeam
  severity: medium
  description: WordPress debug logs can expose sensitive information about the application structure and potential vulnerabilities.
  tags: wordpress,exposure,logs

requests:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/debug.log"
    
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "PHP Notice:"
          - "PHP Warning:"
          - "PHP Error:"
        condition: or
      
      - type: status
        status:
          - 200
```

To run this custom template:

```bash
nuclei -u https://target-wordpress-site.com -t ./wordpress-debug-log.yaml -v
```

### Example: Discovering New CVEs with Custom Templates

This example demonstrates how to create and use a template for a recently disclosed vulnerability:

1. Create a template file `cve-2023-example.yaml`:

```yaml
id: cve-2023-example

info:
  name: Example Application RCE
  author: RedTeamer
  severity: critical
  description: Remote code execution vulnerability in Example Application
  reference: https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX
  tags: cve,cve2023,rce,example-app

requests:
  - raw:
      - |
        POST /api/process HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        
        {"action":"ping","target":"127.0.0.1; id #"}

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "uid="
          - "gid="
          - "groups="
        condition: and

      - type: status
        status:
          - 200
```

2. Run Nuclei with your custom template:

```bash
nuclei -l targets.txt -t ./cve-2023-example.yaml -o results.txt
```

### Comprehensive Scanning Workflow

For red team engagements, implement this Nuclei workflow:

1. **Initial reconnaissance scan** using general templates:
   ```bash
   nuclei -l subdomains.txt -t nuclei-templates/exposed-panels/ -t nuclei-templates/technologies/ -o tech-recon.txt
   ```

2. **Follow with vulnerability scanning**:
   ```bash
   nuclei -l subdomains.txt -t nuclei-templates/vulnerabilities/ -severity critical,high -o critical-vulns.txt
   ```

3. **Target specific technologies** detected in step 1:
   ```bash
   nuclei -l wordpress-sites.txt -t nuclei-templates/wordpress/ -o wordpress-vulns.txt
   ```

4. **Discover misconfigurations**:
   ```bash
   nuclei -l all-targets.txt -t nuclei-templates/misconfiguration/ -o misconfigs.txt
   ```

5. **Use template filtering** for targeted testing:
   ```bash
   nuclei -l targets.txt -tags sqli,rce,lfi -o injection-vulns.txt
   ```

This structured approach allows for effective prioritization of vulnerabilities based on exploitability and impact, which is essential for efficient red team operations.

## Additional Web Application Scanners

### Arachni

Arachni is a feature-rich, modular web application security scanner framework. It's particularly useful for testing AJAX-heavy applications.

Key features:
- Browser automation for complex workflows
- Session management
- Highly concurrent architecture

Example usage:
```bash
arachni https://target-app.com/ --scope-directory-depth-limit=3 --output-verbose --report-save-path=arachni-report
```

### Vega

Vega is a free and open-source web security scanner and testing platform, featuring an automated scanner and an intercepting proxy.

Key features:
- Subversion scanning
- Content security policy analysis
- Intercepting proxy

Example usage through the GUI:
1. Start Vega
2. Select "Scan" → "Start New Scan"
3. Enter the target URL
4. Configure modules and start scanning

### Sn1per

Sn1per automates the entire penetration testing process, including web application scanning.

Example for web-focused scanning:
```bash
sniper -t https://target-app.com -m webrecon
```

## Conclusion

Web application vulnerability scanners are essential tools in the red team arsenal. Each tool brings unique capabilities and strengths to web application assessment. OWASP ZAP provides a comprehensive interactive testing environment, Skipfish excels at high-speed discovery, Wapiti offers focused vulnerability checks, and Nuclei brings template-based flexibility.

For effective red team operations, consider using these tools in combination. Start with broad discovery using Skipfish, follow with targeted vulnerability identification using ZAP and Wapiti, then use Nuclei for specific known vulnerability checks. This layered approach ensures comprehensive coverage while maximizing efficiency.

Remember that automated tools, while powerful, have limitations. Always supplement automated scanning with manual testing, especially for complex vulnerabilities like business logic flaws that automated scanners may miss. The tools covered in this chapter should be viewed as force multipliers that enhance your manual testing efforts rather than replacing them entirely.
