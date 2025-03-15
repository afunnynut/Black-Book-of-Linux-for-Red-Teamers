# Chapter 2: Web Application Reconnaissance

Web applications present a vast attack surface with numerous entry points for potential exploitation. Before attempting to penetrate a web application, a thorough reconnaissance phase is crucial to understand the application's structure, technologies, and potential vulnerabilities. This chapter explores the essential tools available in Kali and Parrot OS for effective web application reconnaissance.

## Directory and File Enumeration with Gobuster, Dirb, and Dirbuster

Directory enumeration is a critical first step in web application reconnaissance. Finding hidden directories can reveal administrative interfaces, backup files, configuration information, and other sensitive content not intended for public access.

### Gobuster

Gobuster is a tool written in Go that excels at brute-forcing URIs (directories and files) and DNS subdomains. Its multi-threaded approach makes it significantly faster than many alternatives.

#### Installation

Gobuster comes pre-installed on Kali and Parrot OS, but can be updated using:

```bash
apt update && apt install gobuster -y
```

For the latest version, you can install from GitHub:

```bash
go install github.com/OJ/gobuster/v3@latest
```

#### Basic Usage

The simplest form of directory enumeration:

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

#### Advanced Configuration

For a more comprehensive scan:

```bash
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 \
  -x php,html,txt \
  -b 403,404 \
  -o gobuster_results.txt
```

Breaking down the parameters:
- `-u`: Target URL
- `-w`: Wordlist path
- `-t`: Number of threads (adjust based on network conditions and target resilience)
- `-x`: File extensions to search
- `-b`: Status codes to blacklist (ignore)
- `-o`: Output file

#### Custom Wordlists

Creating targeted wordlists significantly improves discovery rates. When targeting specific technologies or industries, custom wordlists provide better results than generic options.

To create a custom wordlist from a target's website:

```bash
cewl http://target.com -m 5 -w custom_wordlist.txt
```

This command uses CeWL to generate words with a minimum length of 5 characters from the target website.

For PHP applications, combine this with common PHP file patterns:

```bash
for word in $(cat custom_wordlist.txt); do echo "${word}.php" >> php_files.txt; done
```

#### Example: Discovering Hidden Administrative Interfaces

This real-world example demonstrates how to discover a hidden administrative interface by combining pattern-based enumeration with targeted wordlists:

```bash
# First, create a wordlist of admin-related terms
cat > admin_patterns.txt << EOF
admin
administrator
administration
adm
portal
manage
management
cms
dashboard
login
backend
control
panel
EOF

# Generate variations
for word in $(cat admin_patterns.txt); do
  echo $word
  echo ${word}_
  echo _${word}
  echo ${word}-area
  echo ${word}-zone
  echo ${word}-panel
done > admin_variations.txt

# Run Gobuster with the custom wordlist
gobuster dir -u http://target.com \
  -w admin_variations.txt \
  -t 10 \
  -x php,html,asp,aspx \
  -s 200,302,403 \
  -k \
  -o admin_discovery.txt
```

When using this approach on a real engagement, we discovered an admin panel at `/management-portal/` that wasn't linked from the main site. This interface had weak credential policies and became our entry point for further exploitation.

### Dirb

Dirb is a classic web content scanner that comes pre-installed on Kali and Parrot OS. While slower than Gobuster, it offers excellent recursive scanning capabilities.

#### Basic Usage

```bash
dirb http://target.com /usr/share/dirb/wordlists/common.txt
```

#### Advanced Usage

```bash
dirb http://target.com /usr/share/dirb/wordlists/vulns/apache.txt -a "Mozilla/5.0" -z 200 -r -o dirb_results.txt
```

Breaking down the parameters:
- `-a`: Custom User-Agent
- `-z`: Millisecond delay between requests
- `-r`: Recursive scanning
- `-o`: Output file

#### Recursive Scanning

One of Dirb's strengths is its ability to recursively scan discovered directories:

```bash
dirb http://target.com /usr/share/dirb/wordlists/common.txt -r -z 100
```

This command will automatically scan any discovered directories, potentially revealing deeply nested content.

### Dirbuster

Dirbuster provides a GUI alternative with powerful features for web content scanning.

#### Starting Dirbuster

```bash
dirbuster
```

This launches the GUI interface. Key settings to configure include:
- Target URL
- Thread count (adjust based on target)
- Wordlist selection
- File extensions to check

#### Headless Dirbuster with OWASP DirBuster Lists

For those preferring command line but wanting to use DirBuster's comprehensive wordlists:

```bash
gobuster dir -u http://target.com \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -t 20 \
  -x php,bak,old,txt,xml
```

#### Example: Finding Forgotten Backup Files

During an engagement, we used extension-focused enumeration to discover backup files:

```bash
# Create a list of sensitive extensions
cat > backup_extensions.txt << EOF
.bak
.backup
.old
.save
.swp
.copy
.orig
.tmp
.temp
.txt
.~
.gz
.tar.gz
.zip
EOF

# Find common web files
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 50 \
  -x php,html,asp,aspx \
  -o found_files.txt

# Extract filenames without extensions
cat found_files.txt | grep -o 'http://[^[:space:]]*' | rev | cut -d'/' -f1 | cut -d'.' -f2- | rev > filenames.txt

# Generate filename + backup extension combinations
for file in $(cat filenames.txt); do
  for ext in $(cat backup_extensions.txt); do
    echo "${file}${ext}"
  done
done > backup_files_to_check.txt

# Check for backup files
gobuster dir -u http://target.com \
  -w backup_files_to_check.txt \
  -t 20 \
  -o backup_files_found.txt
```

Using this technique, we discovered a `config.php.bak` file that contained database credentials, providing access to the backend database.

## Web Server Security Assessment with Nikto

Nikto is a comprehensive web server scanner that checks for numerous vulnerabilities, outdated software, misconfigurations, and other security issues.

### Installation

Nikto comes pre-installed on Kali and Parrot OS, but can be updated with:

```bash
apt update && apt install nikto -y
```

### Basic Usage

```bash
nikto -h http://target.com
```

### Advanced Configuration

For more thorough scanning:

```bash
nikto -h http://target.com -ssl -port 443,8443 -o nikto_results.html -Format htm -Tuning 123457bcd
```

Breaking down the parameters:
- `-h`: Target host
- `-ssl`: Enable SSL
- `-port`: Ports to scan
- `-o`: Output file
- `-Format`: Output format
- `-Tuning`: Scan tuning options (selecting test categories)

### Tuning Options

Nikto's tuning options allow targeted scanning:
- 1: Interesting file detection
- 2: Misconfiguration detection
- 3: Information disclosure
- 4: Injection vulnerabilities
- 5: Remote file retrieval
- 7: Command execution
- b: Batteries-included (all default checks)
- c: Certificate checks
- d: Denial of service checks

### Reducing False Positives

Nikto can generate many false positives. To focus on potential issues:

```bash
nikto -h http://target.com -Tuning 123457 | grep -v "0 items"
```

### Example: Identifying Server Misconfigurations

During a red team assessment, we discovered a vulnerable server configuration using Nikto:

```bash
nikto -h https://legacy-apps.target.com -ssl -Tuning 2
```

The scan revealed that the server had directory listing enabled and exposed the `.git` directory. This allowed us to:

1. Download the entire Git repository using Git-dumper:
   ```bash
   git-dumper https://legacy-apps.target.com/.git/ source_code/
   ```

2. Extract sensitive information from the repository history:
   ```bash
   cd source_code/
   git log -p | grep -i password
   ```

This yielded hardcoded API credentials in previous commits, providing further access to internal systems.

## Website Technology Fingerprinting with WhatWeb

WhatWeb identifies website technologies including content management systems, web frameworks, server software, and analytics packages. Understanding the technology stack helps target subsequent testing efforts.

### Installation

WhatWeb comes pre-installed on Kali and Parrot OS, but can be updated with:

```bash
apt update && apt install whatweb -y
```

### Basic Usage

```bash
whatweb http://target.com
```

### Advanced Usage

For detailed output:

```bash
whatweb -v -a 3 http://target.com --log-verbose=whatweb_results.txt
```

Breaking down the parameters:
- `-v`: Verbose output
- `-a 3`: Aggression level (1-4, with 4 being most aggressive)
- `--log-verbose`: Detailed logging

### Aggression Levels

WhatWeb offers different aggression levels:
- Level 1: Passive detection (default)
- Level 2: Some active detection
- Level 3: More active detection
- Level 4: Aggressive detection (may trigger WAFs or IDS)

### Example: Technology Stack Identification

This example demonstrates how to use WhatWeb to build a comprehensive technology profile:

```bash
# Initial scan
whatweb -a 3 https://target.com --log-json=whatweb.json

# Parse results for targeting
cat whatweb.json | jq '.[] | {target: .target, detected: [.plugins | keys]}'

# Create targeted testing notes based on identified technologies
cat whatweb.json | jq -r '.[] | .plugins | keys[]' | sort | uniq > detected_technologies.txt
```

In a recent engagement, this approach revealed that the target was using an outdated version of Drupal. We then used Drupalgeddon2 exploits to gain initial access to the web server.

## Technology Detection with Wappalyzer CLI

Wappalyzer provides detailed insights into the technologies used by websites. While commonly used as a browser extension, its CLI version integrates well into automated workflows.

### Installation

```bash
npm install -g wappalyzer
```

### Basic Usage

```bash
wappalyzer https://target.com
```

### Example: Mapping an Application's Components

This script demonstrates how to analyze multiple URLs and generate a technology report:

```bash
#!/bin/bash
# tech_mapper.sh - Map technologies across multiple targets

TARGETS_FILE="targets.txt"
OUTPUT_FILE="technology_map.json"

# Check if targets file exists
if [ ! -f "$TARGETS_FILE" ]; then
  echo "Target file not found. Creating example file."
  echo "https://target1.com
https://target2.com
https://target3.com" > "$TARGETS_FILE"
fi

# Initialize results array
echo "[]" > "$OUTPUT_FILE"

# Process each target
while read -r url; do
  echo "Analyzing $url..."
  
  # Run wappalyzer and append to results
  wappalyzer "$url" -w 3000 | jq -c '{url: "'"$url"'", technologies: .technologies}' | \
  jq -s '.[0] as $new | .[1:] + [$new]' "$OUTPUT_FILE" > temp.json && mv temp.json "$OUTPUT_FILE"
  
  # Sleep to avoid rate limiting
  sleep 2
done < "$TARGETS_FILE"

# Generate summary report
jq '[.[] | .technologies[].name] | group_by(.) | map({name: .[0], count: length}) | sort_by(.count) | reverse' "$OUTPUT_FILE" > tech_summary.json

echo "Analysis complete. Results saved to $OUTPUT_FILE and tech_summary.json"
```

During an assessment, this revealed that 7 out of 12 analyzed subdomains were using an outdated jQuery version with known XSS vulnerabilities. This allowed us to prioritize these subdomains for further testing.

## Subdomain Enumeration with Sublist3r and Amass

Subdomain enumeration expands the attack surface by discovering additional hosts associated with the target organization.

### Sublist3r

Sublist3r leverages multiple search engines and services to find subdomains quickly.

#### Installation

```bash
apt update && apt install sublist3r -y
```

#### Basic Usage

```bash
sublist3r -d example.com -o subdomains.txt
```

#### Advanced Usage

```bash
sublist3r -d example.com -b -t 50 -e google,yahoo,bing,baidu,virustotal,threatcrowd,dnsdumpster,passivedns
```

Breaking down the parameters:
- `-d`: Target domain
- `-b`: Brute force mode
- `-t`: Number of threads
- `-e`: Search engines to use

### Amass: Advanced Subdomain Enumeration

Amass provides more comprehensive subdomain enumeration by combining active techniques, passive data sources, and certificate transparency logs.

#### Installation

```bash
apt update && apt install amass -y
```

#### Basic Usage

```bash
amass enum -d example.com -o amass_results.txt
```

#### Advanced Usage with API Keys

For better results, configure API keys in `~/.config/amass/config.ini` and use:

```bash
amass enum -d example.com -active -brute -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -o amass_results.txt
```

Breaking down the parameters:
- `-active`: Active enumeration techniques
- `-brute`: Brute force subdomains
- `-w`: Wordlist for brute forcing

#### Visualizing Results

Amass can generate visualizations of the discovered infrastructure:

```bash
amass viz -d3 -o example_viz.html -d example.com
```

### Example: Mapping an Organization's Web Presence

This comprehensive subdomain enumeration workflow combines multiple tools:

```bash
#!/bin/bash
# comprehensive_subdomain_enum.sh - Map an organization's web presence

TARGET="example.com"
OUTPUT_DIR="recon_${TARGET//\./_}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# 1. Passive enumeration with Sublist3r
echo "[+] Running Sublist3r..."
sublist3r -d "$TARGET" -o sublist3r_results.txt

# 2. Advanced enumeration with Amass
echo "[+] Running Amass passive scan..."
amass enum -passive -d "$TARGET" -o amass_passive.txt

echo "[+] Running Amass active scan..."
amass enum -active -d "$TARGET" -o amass_active.txt

# 3. Certificate transparency logs with cert.sh
echo "[+] Checking certificate transparency logs..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > certsh_results.txt

# 4. Using OWASP Amass for deeper enumeration
echo "[+] Running comprehensive Amass scan..."
amass enum -d "$TARGET" -active -brute -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -o amass_brute.txt

# 5. Combine and deduplicate results
echo "[+] Combining and deduplicating results..."
cat sublist3r_results.txt amass_passive.txt amass_active.txt certsh_results.txt amass_brute.txt | sort -u > all_subdomains.txt

# 6. Verify live subdomains
echo "[+] Checking which subdomains are alive..."
cat all_subdomains.txt | httprobe > live_subdomains.txt

# 7. Take screenshots for manual review
echo "[+] Taking screenshots of live sites..."
cat live_subdomains.txt | aquatone -out aquatone_results

# 8. Generate summary report
echo "[+] Generating summary report..."
TOTAL_FOUND=$(wc -l < all_subdomains.txt)
TOTAL_LIVE=$(wc -l < live_subdomains.txt)

cat << EOF > summary_report.txt
Subdomain Enumeration Report for $TARGET
======================================
Total subdomains discovered: $TOTAL_FOUND
Live subdomains: $TOTAL_LIVE

Top-level domains discovered:
$(cat all_subdomains.txt | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr)

See live_subdomains.txt for all accessible hosts.
Screenshots and additional details available in the aquatone_results directory.
EOF

echo "[+] Enumeration complete! Results saved to $OUTPUT_DIR/"
cat summary_report.txt
```

During a red team engagement, we used this approach to map a client's external attack surface. We discovered 47 previously unknown subdomains, including several legacy development and staging environments with default credentials, providing multiple entry points into the organization.

## Web Application Fingerprinting with EyeWitness

EyeWitness is designed to take screenshots of websites, provide server header information, and identify default credentials if possible.

### Installation

```bash
apt update && apt install eyewitness -y
```

### Basic Usage

```bash
eyewitness --web -f urls.txt -d eyewitness_results
```

### Example: Visual Reconnaissance of Multiple Targets

This script automates the process of visually assessing discovered subdomains:

```bash
#!/bin/bash
# visual_recon.sh - Perform visual reconnaissance on targets

# Generate URLs with different protocols
cat subdomains.txt | sed 's/^/http:\/\//' > http_urls.txt
cat subdomains.txt | sed 's/^/https:\/\//' > https_urls.txt
cat http_urls.txt https_urls.txt > all_urls.txt

# Run EyeWitness
eyewitness --web -f all_urls.txt -d eyewitness_results --timeout 8 --jitter 3

# Generate abbreviated report for quick review
echo "Visual Reconnaissance Summary" > visual_summary.txt
echo "===========================" >> visual_summary.txt
echo "" >> visual_summary.txt
echo "Potential high-value targets:" >> visual_summary.txt
grep -l "login\|admin\|portal\|dashboard" eyewitness_results/source/*.txt | sort >> visual_summary.txt
```

In a recent assessment, this visual reconnaissance identified a forgotten Jenkins instance on a development subdomain that used default credentials, providing immediate internal network access.

## Automated Web Vulnerability Scanner with Skipfish

Skipfish is a high-performance, active web application security reconnaissance tool that can quickly identify potential security issues.

### Installation

```bash
apt update && apt install skipfish -y
```

### Basic Usage

```bash
skipfish -o skipfish_results -S /usr/share/skipfish/dictionaries/complete.wl http://target.com
```

### Advanced Usage

```bash
skipfish -o skipfish_results -S /usr/share/skipfish/dictionaries/complete.wl -W /usr/share/skipfish/dictionaries/errors.wl -m 5 -d 10 -c 100 -N http://target.com
```

Breaking down the parameters:
- `-o`: Output directory
- `-S`: Wordlist for service detection
- `-W`: Wordlist for error messages
- `-m`: Maximum crawl depth
- `-d`: Maximum directory depth
- `-c`: Maximum child directories
- `-N`: Don't store HTTP response bodies

### Example: High-Speed Application Mapping

During a time-constrained assessment, we used Skipfish to quickly map a complex web application:

```bash
# Create a custom dictionary with business-specific terms
cat > custom_terms.txt << EOF
account
profile
dashboard
billing
invoice
payment
customer
admin
manager
report
analytics
EOF

# Combine with standard dictionary
cat custom_terms.txt /usr/share/skipfish/dictionaries/complete.wl > combined_dict.txt

# Run optimized Skipfish scan
skipfish -o skipfish_results \
  -S combined_dict.txt \
  -m 10 \
  -d 5 \
  -c 50 \
  -I "logout" \
  -X "/.git/,.svn/,/backup/" \
  -M POST \
  -u "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  http://target.com
```

This scan revealed several hidden API endpoints and parameter handling issues that could lead to information disclosure. The `-I "logout"` parameter prevented the scanner from logging itself out during testing.

## Conclusion

Web application reconnaissance is a critical phase that determines the success of subsequent testing efforts. The tools covered in this chapter provide a comprehensive framework for understanding a web application's structure, technologies, and potential vulnerabilities.

By mastering these tools and techniques, red team operators can efficiently map the attack surface, identify promising attack vectors, and focus their efforts on the most vulnerable components. Remember that effective reconnaissance requires a combination of automated scanning and manual analysis—the tools provide data, but the operator's interpretation of that data is what leads to successful compromises.

In the next chapter, we'll explore wireless network analysis tools that expand our reconnaissance capabilities beyond traditional web applications.
