# Chapter 21: Forensics Tools for Red Teamers

## Introduction to Digital Forensics for Red Teams

As a red team operator, understanding forensics tools is crucial not only for extracting valuable intelligence but also for knowing exactly what artifacts your activities create. This knowledge allows you to operate with greater stealth, anticipate investigators' actions, and develop more effective anti-forensics strategies. While blue teams use these tools to detect intrusions, red teamers leverage them to understand their own digital footprint and develop methods to minimize it.

This chapter explores essential forensics tools that every red team professional should master, focusing on how these tools work, what they can recover, and critically, how to account for their capabilities in your operations.

![Digital forensics workflow](./images/forensics_workflow.png)
*Figure 21.1: Simplified digital forensics workflow with common tools*

## File Carving with Foremost and Scalpel

### Introduction to File Carving

File carving is the process of extracting files from a disk image or memory dump without relying on file system metadata. These techniques work by identifying file signatures (headers and footers) and extracting data between them. For red teamers, understanding file carving is critical because:

1. It reveals what data remains recoverable even after deletion
2. It demonstrates how fragments of your tools, scripts, or exfiltrated data may persist
3. It provides insight into developing effective anti-forensics countermeasures

### Foremost: The Original File Carver

Foremost was originally developed by the United States Air Force Office of Special Investigations and has become a staple in digital forensics toolkits.

#### Basic Usage

```bash
# Simple file carving from a disk image
sudo foremost -i /dev/sdb -o recovered_files

# Carve specific file types
sudo foremost -t pdf,jpg,doc -i disk_image.dd -o recovered_files

# Verbose output with detailed logging
sudo foremost -v -i memory.dmp -o recovered_files
```

#### Understanding Foremost's Configuration

Foremost uses a configuration file (`/etc/foremost.conf`) that defines file signatures. Examining this file provides invaluable insight into what investigators look for:

```bash
# Examine foremost's detection signatures
grep -v "^#" /etc/foremost.conf | grep -v "^$"
```

The configuration contains entries like:

```
jpg     y       200000000       \xff\xd8\xff
pdf     y       5000000         %PDF-  %EOF\x0d
exe     y       5000000         MZ
zip     y       10000000        PK\x03\x04      \x3c\xac
```

Each entry includes:
- File extension
- Whether to enable case sensitivity
- Maximum file size to extract
- Header signature (and optional footer)

#### Foremost Operational Analysis

Let's look at what happens when Foremost runs:

```bash
# Create a test disk image
dd if=/dev/zero of=test.dd bs=1M count=100
echo "This is secret PDF data %PDF-1.5 test" | dd conv=notrunc bs=1 seek=1000 of=test.dd
echo "This is a JPEG file \xff\xd8\xff test" | dd conv=notrunc bs=1 seek=50000 of=test.dd

# Run foremost
sudo foremost -v -i test.dd -o test_recovery
```

Foremost will:
1. Scan the entire image byte by byte
2. Look for patterns matching known file headers
3. Extract data until it reaches a footer or maximum file size
4. Save the carved files in the output directory organized by file type

**Red Team Implications:**

Even if you delete files or wipe free space, file fragments may remain recoverable if they contain identifiable headers. Some key considerations:

1. Deleted tools, exploits, or exfiltrated data can be recovered
2. Fragments in swap files, hibernation files, or memory dumps are also vulnerable
3. Media that has been quick-formatted (not zero-wiped) retains most data

> **RED TEAM TIP:**
>
> When conducting operations, remember that merely deleting sensitive files is insufficient. Consider these countermeasures:
>
> 1. Use tools that don't write to disk (memory-only execution)
> 2. Encrypt payloads so that carved fragments remain unreadable
> 3. Overwrite files with random data before deletion
> 4. For critical operations, use in-memory file systems like tmpfs

### Scalpel: The Surgical File Carver

Scalpel, a fork of Foremost, provides more efficient and precise file carving with a lower memory footprint. Its enhanced performance makes it particularly useful for large disk images.

#### Basic Usage

```bash
# Basic file carving
sudo scalpel -o recovered_files disk_image.dd

# Specify configuration file with custom signatures
sudo scalpel -c custom_scalpel.conf -o recovered_files disk_image.dd

# Preview mode (scan without recovery)
sudo scalpel -p -o recovered_files disk_image.dd
```

#### Creating Custom Signatures

One of Scalpel's strengths is its ability to use custom signatures, which is valuable for recovering specific artifacts or understanding what custom tools might leave behind:

```bash
# Creating a custom signature for a proprietary file format
echo "custom  y       1000000   MYHEADER    FOOTER" >> custom_scalpel.conf
sudo scalpel -c custom_scalpel.conf -o recovered_files disk_image.dd
```

#### Performance Comparison

Scalpel significantly outperforms Foremost for large images:

| Tool | 40GB Image Recovery Time | Memory Usage | CPU Usage |
|------|--------------------------|--------------|-----------|
| Foremost | ~120 minutes | ~200-300MB | Moderate |
| Scalpel | ~45 minutes | ~50-100MB | High |

#### Scalpel vs. Foremost: Key Differences

1. Scalpel performs a two-pass approach:
   - First pass identifies potential files
   - Second pass extracts them
2. Scalpel uses more efficient memory structures
3. Scalpel has better handling of fragmented files

**Red Team Considerations:**

Understanding Scalpel's capabilities helps you assess what forensic investigators might recover from systems you've accessed:

1. Encryption becomes even more important as Scalpel can recover fragmented files
2. Tools that modify their own headers to avoid detection are more effective
3. Memory-only operations remain the safest approach for sensitive tasks

> **CASE STUDY: The Recovered Toolset**
> 
> During a red team exercise in 2022, an operator installed tools on a target server but believed they had been securely removed. The blue team used Scalpel to recover fragments of a custom backdoor from disk slack space. Because the backdoor contained hardcoded C2 infrastructure, this allowed the blue team to identify other compromised systems.
>
> The lesson: Even temporary staging of tools can leave recoverable artifacts. Always assume file carving will be used during incident response.

## Autopsy and The Sleuth Kit: Comprehensive Digital Forensics

While file carving tools focus on recovering file content, The Sleuth Kit (TSK) and its graphical interface Autopsy provide a comprehensive framework for digital forensics. These tools allow investigators to analyze file systems, registry entries, web artifacts, and much more.

### The Sleuth Kit (TSK) Core Tools

The Sleuth Kit consists of command-line utilities for investigating volume and file system data:

| Command | Purpose | Example Usage |
|---------|---------|---------------|
| `mmls` | Display partition table | `mmls disk_image.dd` |
| `fsstat` | File system statistics | `fsstat -o 2048 disk_image.dd` |
| `fls` | List files and directories | `fls -o 2048 disk_image.dd` |
| `istat` | Display inode details | `istat -o 2048 disk_image.dd 16` |
| `icat` | Output file contents by inode | `icat -o 2048 disk_image.dd 16 > extracted_file` |
| `ils` | List inode information | `ils -o 2048 disk_image.dd` |
| `blkcat` | Display block contents | `blkcat -o 2048 disk_image.dd 123` |

#### Basic TSK Workflow

To understand what investigators might discover about your operations, let's examine a typical workflow:

```bash
# 1. Identify partitions
sudo mmls disk_image.dd

# Sample output:
# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#      Slot    Start        End          Length       Description
#      00:  -----    0000000000   0000000000   0000000001   Primary Table (#0)
#      01:  -----    0000000001   0000000062   0000000062   Unallocated
#      02:  00:00    0000000063   0209712509   0209712447   NTFS (0x07)

# 2. Extract file system details (note offset from partition table)
sudo fsstat -o 63 disk_image.dd

# 3. List files and directories (including deleted ones)
sudo fls -o 63 disk_image.dd

# 4. Examine specific directory
sudo fls -o 63 disk_image.dd 5

# 5. Extract file content by inode
sudo icat -o 63 disk_image.dd 16 > recovered_file.txt
```

This sequence reveals how forensic investigators navigate through file systems to discover your activities.

#### Recoverable Artifacts

TSK can recover numerous artifacts relevant to red team operations:

1. Deleted files that have not been overwritten
2. File creation and access timestamps
3. Directory structures, even after deletion
4. File system journal entries showing file operations
5. Slack space data (partial content in allocated but unused space)

### Autopsy: The Graphical Interface

Autopsy provides an intuitive interface for TSK functionality plus additional features like keyword searching, hash filtering, and timeline analysis.

#### Key Autopsy Features

1. **Timeline Analysis**: Visualizes system activity across time
2. **Keyword Search**: Finds specific terms across the entire image
3. **Web Artifacts**: Recovers browser history, cache, and downloads
4. **Registry Analysis**: Examines Windows registry for system configuration
5. **Hash Lookup**: Identifies known files using hash databases

#### Creating a Basic Autopsy Case

```bash
# Launch Autopsy (may vary by distribution)
sudo autopsy
```

Then access the web interface at `http://localhost:9999/autopsy` and follow these steps:

1. Create a new case
2. Add a forensic image
3. Configure initial ingest modules
4. Begin analysis

![Autopsy interface](./images/autopsy_interface.png)
*Figure 21.2: Autopsy interface showing timeline analysis*

#### Red Team Considerations for File System Forensics

Understanding TSK and Autopsy capabilities helps you develop more effective anti-forensics strategies:

1. **Timestamp Manipulation**: Investigators can compare multiple timestamps (Modified-Accessed-Created) for inconsistencies
2. **File System Journaling**: Operations on journaling file systems leave records even after file deletion
3. **Registry Artifacts**: Windows systems maintain extensive registry records of program execution
4. **File Signature Analysis**: Renamed files can be identified by their true type

**Advanced Anti-Forensics Techniques:**

```bash
# Change file timestamps to match surrounding files
touch -r /etc/passwd backdoor.sh

# Disable journaling (requires remounting, potentially suspicious)
sudo tune2fs -O ^has_journal /dev/sda1

# Execute from alternate data streams (Windows)
type backdoor.exe > legitimate.txt:hidden.exe
start legitimate.txt:hidden.exe
```

> **WARNING**
> 
> These anti-forensics techniques may trigger security alerts on monitored systems. Always operate within the scope of your engagement and authorization.

## Volatility: Memory Forensics Framework

While disk forensics examines persistent storage, memory forensics analyzes the volatile memory (RAM) of a running system. Volatility is the leading open-source memory forensics framework, capable of extracting processes, network connections, encryption keys, and much more from memory dumps.

### Why Memory Forensics Matters to Red Teams

For red teamers, understanding memory forensics is crucial because:

1. Many fileless malware techniques operate exclusively in memory
2. Memory contains decrypted versions of otherwise encrypted data
3. Memory analysis can reveal network connections and running processes
4. Advanced detection tools increasingly use memory scanning

### Basic Volatility Usage

Volatility works with memory dumps captured from target systems. The first step is always to identify the correct profile (OS version and architecture):

```bash
# Identify the memory dump profile
volatility -f memory.dmp imageinfo

# List running processes
volatility -f memory.dmp --profile=Win10x64_19041 pslist

# View network connections
volatility -f memory.dmp --profile=Win10x64_19041 netscan

# Dump process memory
volatility -f memory.dmp --profile=Win10x64_19041 memdump -p 1234 -D output/
```

### Key Volatility Plugins for Red Teams

Understanding what Volatility can extract helps you assess your operational security:

| Plugin | Purpose | Red Team Implications |
|--------|---------|------------------------|
| `pslist`/`psscan` | List processes | Shows your running tools even if hidden from task manager |
| `netscan` | Network connections | Reveals C2 connections and their process owners |
| `malfind` | Identify injected code | Detects process injection techniques |
| `dlllist` | List loaded DLLs | Shows malicious DLLs loaded by processes |
| `cmdline` | Show process command lines | Reveals execution parameters and artifacts |
| `hashdump` | Extract password hashes | Can extract credential artifacts from your sessions |
| `mimikatz` | Extract passwords from memory | Can find plaintext credentials you've accessed |
| `yarascan` | Scan memory with YARA rules | Can detect signatures of known tools |

### Memory Artifacts Analysis

Let's examine what memory analysis might reveal about different red team techniques:

#### Process Injection Artifacts

```bash
# Examine for injected code
volatility -f memory.dmp --profile=Win10x64_19041 malfind

# Analyze a specific suspicious process
volatility -f memory.dmp --profile=Win10x64_19041 memdump -p 4728 -D output/
strings output/4728.dmp | grep -i "beacon\|cobalt\|meterpreter"
```

Process injection typically leaves detectable patterns:
- Memory regions with execute permissions that aren't backed by files on disk
- Suspicious memory protection transitions
- Memory pages containing shellcode signatures

#### Network Connection Artifacts

```bash
# Examine active and recently closed connections
volatility -f memory.dmp --profile=Win10x64_19041 netscan
```

This reveals:
- All TCP/UDP connections and their process owners
- Listening ports that might indicate backdoors
- Recently closed connections that could reveal C2 infrastructure

#### Command Execution Artifacts

```bash
# Examine command history
volatility -f memory.dmp --profile=Win10x64_19041 cmdscan
volatility -f memory.dmp --profile=Win10x64_19041 consoles
```

These commands can recover:
- Recently executed console commands
- Command output still in buffer memory
- PowerShell command history and scripts

### Memory-Resident Malware Techniques

Understanding how malware persists in memory helps red teamers develop more sophisticated techniques:

1. **Process Hollowing**: Replacing legitimate process memory with malicious code
   ```bash
   # Detectable via:
   volatility -f memory.dmp --profile=Win10x64_19041 hollowfind
   ```

2. **DLL Injection**: Forcing a process to load a malicious DLL
   ```bash
   # Detectable via:
   volatility -f memory.dmp --profile=Win10x64_19041 dlllist -p 1234
   ```

3. **Reflective Loading**: Loading a DLL without using standard Windows API calls
   ```bash
   # Detectable via:
   volatility -f memory.dmp --profile=Win10x64_19041 malfind
   ```

4. **Atom Bombing**: Using Windows atom tables for code injection
   ```bash
   # Harder to detect, but memory patterns still exist
   volatility -f memory.dmp --profile=Win10x64_19041 yarascan -Y "pattern"
   ```

### Advanced Memory Analysis

Volatility can perform deeper analysis using custom plugins:

```bash
# Scan for Cobalt Strike beacons
volatility --plugins=/path/to/plugins/ -f memory.dmp --profile=Win10x64_19041 cobaltstrike

# Hunt for YARA signatures
volatility -f memory.dmp --profile=Win10x64_19041 yarascan -y rules/malware.yar
```

> **RED TEAM TIP:**
>
> To minimize memory artifacts:
>
> 1. Keep payloads small and modular
> 2. Regularly refresh/reboot implants to clear memory
> 3. Avoid writing tools that use distinctive string patterns
> 4. Use obfuscation and encryption for strings in memory
> 5. Consider direct syscall implementations instead of API calls
> 6. Use living-off-the-land techniques that blend with normal operations

## Extundelete: File Recovery and Secure Deletion

For red teamers, understanding how deleted files can be recovered is essential for both exfiltrating data and ensuring your own operational security. Extundelete is a powerful utility for recovering deleted files from ext3/ext4 file systems.

### Basic Extundelete Usage

```bash
# Recover all deleted files from a partition
sudo extundelete /dev/sdb1 --restore-all

# Recover a specific deleted file
sudo extundelete /dev/sdb1 --restore-file path/to/deleted/file

# Recover a specific deleted directory and its contents
sudo extundelete /dev/sdb1 --restore-directory path/to/deleted/directory

# Recover files deleted after a specific time
sudo extundelete /dev/sdb1 --after 2023-09-01
```

### How File Recovery Works

Understanding the mechanics of file recovery provides insight into developing secure deletion methods:

1. When a file is "deleted":
   - The file's entry is removed from the directory
   - The file's inode is marked as available
   - The data blocks are marked as free
   - **But the actual data remains until overwritten**

2. Recovery tools like Extundelete:
   - Scan the file system for inodes marked as deleted
   - Identify which blocks belonged to those inodes
   - Rebuild the directory structure and file content
   - Save the recovered files to a specified location

### Secure Deletion Techniques

As a red teamer, you must understand how to ensure sensitive data cannot be recovered:

**Basic File Overwriting:**

```bash
# Overwrite a file with zeros before deletion
dd if=/dev/zero of=sensitive_file bs=1M conv=notrunc

# Use shred for more secure overwriting
shred -uzn 3 sensitive_file
```

**Secure Free Space Wiping:**

```bash
# Create a large file that fills free space
dd if=/dev/urandom of=wipe.file bs=1M

# Delete the file, leaving random data in free space
rm wipe.file
```

**Block Device Wiping:**

```bash
# Completely wipe a drive (destructive!)
sudo dd if=/dev/urandom of=/dev/sdb bs=4M status=progress

# More efficient wiping with specific tools
sudo wipe -q -Q 3 /dev/sdb
```

### Testing Recovery Resistance

To verify your secure deletion techniques, you can test recoverability:

```bash
# Create test file
echo "SECRET DATA" > test_secure_delete.txt

# Apply secure deletion method
shred -uzn 3 test_secure_delete.txt

# Attempt recovery
sudo extundelete /dev/sda1 --restore-file test_secure_delete.txt
```

If your deletion was truly secure, recovery attempts should fail or produce unusable data.

### File System-Specific Considerations

Different file systems handle deletion differently, affecting recovery possibilities:

| File System | Recovery Difficulty | Key Considerations |
|-------------|---------------------|-------------------|
| ext3/ext4 | Moderate | Journal can contain file contents |
| NTFS | High | Multiple data streams, MFT residuals |
| FAT32 | High | Simple allocation table makes recovery easier |
| ZFS/btrfs | Very High | Copy-on-write features preserve old versions |
| SSD (any FS) | Variable | TRIM commands and wear leveling affect recovery |

### Recovering Deleted Data from Remote Systems

As a red teamer, you might need to recover deleted data during an operation:

```bash
# Create disk image without mounting (to prevent writing)
sudo dd if=/dev/sda of=disk.img bs=4M status=progress

# Mount image read-only
sudo mount -o ro,loop disk.img /mnt/evidence

# Run extundelete on the mounted image
sudo extundelete /mnt/evidence --restore-all --output-dir recovered_files
```

> **OPERATIONAL SECURITY NOTE:**
>
> When conducting red team operations, remember that:
>
> 1. Wiping tools leave their own evidence of use
> 2. Secure deletion operations often take significant time
> 3. Large write operations may trigger monitoring alerts
> 4. The most secure approach is to never write sensitive data to disk

## Integrating Forensics Knowledge into Red Team Operations

Understanding forensic techniques allows you to conduct more effective operations by anticipating what artifacts you create and how they might be discovered.

### Operational Recommendations

1. **Pre-Operation Planning**:
   - Research target systems to understand their forensic capabilities
   - Plan for both disk and memory artifact minimization
   - Prepare secure communication channels for data exfiltration

2. **During Operations**:
   - Use memory-resident tools whenever possible
   - Encrypt sensitive files before storing them, even temporarily
   - Be aware of timestamps and logs your activities generate
   - Leverage living-off-the-land techniques to blend with normal system activity

3. **Post-Operation Cleanup**:
   - Understand that complete artifact removal is nearly impossible
   - Focus on removing high-value indicators rather than all traces
   - Consider the forensic implications of your cleanup methods themselves

### Creating Forensically-Sound Testing Environments

To improve your operational security, create environments to test your tools against forensic analysis:

```bash
# Create test disk image
dd if=/dev/zero of=test_image.dd bs=1M count=1000

# Format with ext4
sudo losetup /dev/loop0 test_image.dd
sudo mkfs.ext4 /dev/loop0

# Mount the image
sudo mount /dev/loop0 /mnt/test

# Perform test operations
cd /mnt/test
# [conduct your operations]

# Capture memory dump
sudo dd if=/proc/kcore of=memory.dmp bs=1M count=1024

# Unmount
sudo umount /mnt/test
sudo losetup -d /dev/loop0

# Now analyze with forensic tools
sudo autopsy
# [or other tools covered in this chapter]
```

This workflow allows you to see exactly what artifacts your tools and techniques create, enabling continuous improvement of your operational security.

## Conclusion

Forensic tools are dual-purpose for red teamers: they help both recover valuable data from target systems and understand how to minimize your own operational footprint. By mastering these tools, you gain insight into what investigators might discover about your activities, allowing you to refine your techniques for future operations.

The most sophisticated red teams incorporate forensic knowledge throughout their methodology, operating with the constant awareness that their actions create artifacts. They balance operational effectiveness with artifact minimization, understanding that perfect stealth is impossible but significant improvements are always achievable.

In the next chapter, we'll examine reporting and documentation tools that help you consolidate findings and communicate results effectively to stakeholders.

## Additional Resources

- [The Sleuth Kit and Autopsy Documentation](https://www.sleuthkit.org/autopsy/docs.php)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [SANS Forensic Analysis Cheat Sheet](https://digital-forensics.sans.org/media/Poster-2020-Digital-Forensics-DFIR.pdf)
- [Digital Forensics with Open Source Tools](https://www.sciencedirect.com/book/9781597495868/digital-forensics-with-open-source-tools) by Cory Altheide and Harlan Carvey
- [Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099) by Michael Hale Ligh et al.
