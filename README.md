# Container Detection CLI with POC Exploits

A comprehensive educational tool for detecting container environments and demonstrating proof-of-concept exploits for container escape vulnerabilities. Supports both local and remote scanning via SSH.

## Features

### Detection Capabilities

- **Cgroup Analysis**: Detects Docker, LXC, and Kubernetes pods via `/proc/1/cgroup`
- **Environment Variables**: Identifies container-related environment markers
- **Process Analysis**: Checks PID 1 to detect non-standard init processes
- **Mount Point Analysis**: Scans for overlay, aufs, and devicemapper filesystems
- **Docker Socket Detection**: Identifies accessible Docker sockets (security risk)
- **Privileged Container Detection**: Checks for access to `/dev/mem`
- **Multi-Container Support**: Works with Docker, LXC, Kubernetes, ECS, and more

### Exploitation POCs

- **Docker Socket Escape**: Demonstrates container escape via exposed Docker socket
- **Privileged Container Escape**: Shows kernel memory exploitation capabilities
- **Environment Variable Extraction**: Extracts sensitive credentials and API keys
- **Cgroup Escape**: Identifies resource limit bypass opportunities
- **Process Namespace Escape**: Enumerates host processes from container
- **Capability Abuse**: Detects dangerous Linux capabilities

### Scanning Modes

- **Local Detection**: Analyze the current system
- **Remote Scanning**: Scan other systems via SSH with credentials/keys
- **Verbose Mode**: Detailed debugging output
- **JSON Export**: Save findings for reports and automation

## Installation

### Requirements

- Python 3.6+
- SSH client (for remote scanning)
- Linux/Unix system

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/container-detection-cli.git
cd container-detection-cli

# Make executable
chmod +x container_detection_remote.py

# Run
./container_detection_remote.py --local
```

## Usage

### Local Detection

```bash
# Basic scan
./container_detection_remote.py --local

# Verbose output with debug info
./container_detection_remote.py --local -v

# Export results to JSON
./container_detection_remote.py --local --output report.json

# Disable colored output
./container_detection_remote.py --local --no-color
```

### Remote Scanning via SSH

```bash
# Scan with default root user
./container_detection_remote.py --remote 192.168.1.100

# Custom SSH user and port
./container_detection_remote.py --remote example.com --user ubuntu --port 2222

# Using SSH key authentication
./container_detection_remote.py --remote 192.168.1.100 --user ec2-user --key ~/.ssh/id_rsa

# Verbose remote scan
./container_detection_remote.py --remote 192.168.1.100 --user root -v

# Export remote scan
./container_detection_remote.py --remote 192.168.1.100 --output remote_scan.json
```

### Running Exploits

```bash
# Run all available POC exploits locally
./container_detection_remote.py --local --all-exploits

# Run specific exploit
./container_detection_remote.py --local --exploit docker_socket_escape

# Run exploits on remote system
./container_detection_remote.py --remote 192.168.1.100 --user root --all-exploits

# Run specific remote exploit
./container_detection_remote.py --remote 192.168.1.100 --exploit privileged_container_escape
```

### Help

```bash
./container_detection_remote.py --help
```

## Output Examples

### Local Container Detection

```
╔══════════════════════════════════════════════════════════╗
║ CONTAINER DETECTION CLI WITH REMOTE SSH SUPPORT         ║
║ Use only on authorized systems                          ║
╚══════════════════════════════════════════════════════════╝

============================================================
        CONTAINER SECURITY ASSESSMENT REPORT
============================================================

✓ Running in container environment
ℹ Container Type: Docker
Timestamp: 2025-12-01T16:40:00.000000
Target: localhost

Detection Methods:
  • cgroup analysis (docker)
  • mount type: overlay

Detection Summary:
ℹ Positive Checks: 2/6

⚠ SECURITY WARNINGS:
⚠ Docker socket accessible at /var/run/docker.sock

✓ SECURITY RECOMMENDATIONS:
  1. Run containers as non-root users: docker run --user 1000:1000
  2. Drop all capabilities: docker run --cap-drop=ALL
  3. Use read-only filesystems where possible: docker run --read-only
  ...
```

### Remote Scan Output

```
ℹ Connecting to ubuntu@192.168.1.100:22...
✓ Connected to remote host!

============================================================
        CONTAINER SECURITY ASSESSMENT REPORT - 192.168.1.100
============================================================

✓ Running in container environment
ℹ Container Type: Kubernetes Pod
...
```

### Exploit Output

```
[EXPLOIT] Attempting Docker socket escape...

ℹ Found accessible Docker socket: /var/run/docker.sock
POC: Would execute the following command:
docker -H unix:///var/run/docker.sock run -it -v /:/host ubuntu bash
⚠ This would mount the host filesystem inside a new container
Allowing full host filesystem access and potential privilege escalation
```

## Detection Methods

### Cgroup Analysis (`/proc/1/cgroup`)

Reads the cgroup information of the init process to identify container type:
- `docker` - Docker container
- `lxc` - LXC container
- `kubepods` - Kubernetes pod
- Missing `systemd`/`init` - Generic container

### Environment Variables

Checks for container-specific environment variables:
- `DOCKER_HOST`
- `container`
- `KUBERNETES_SERVICE`
- `MESOS_CONTAINER`
- `ECS_CONTAINER`

### PID 1 Process Analysis (`/proc/1/comm`)

Examines the process name of PID 1:
- Containers typically run applications directly as PID 1
- Not `init` or `systemd` indicates container environment

### Mount Points (`/proc/mounts`)

Scans for container-specific filesystem types:
- `overlay` - Docker overlay2 storage
- `aufs` - Docker aufs storage
- `devicemapper` - Docker devicemapper storage
- `docker` - Docker volumes
- `lxcfs` - LXC filesystem

### Docker Socket Detection

Checks for accessible Docker sockets at:
- `/var/run/docker.sock`
- `/run/docker.sock`

### Privileged Container Detection

Checks for access to privileged devices:
- `/dev/mem` - Host memory access (critical vulnerability)

## Vulnerability Definitions

### Docker Socket Escape (CRITICAL)

**Description**: Docker socket accessible from within a container allows executing arbitrary Docker commands on the host.

**Impact**: Complete host compromise, escape from container isolation

**Mitigation**: Never mount Docker socket in containers, use proper role-based access control

### Privileged Container Escape (CRITICAL)

**Description**: Access to `/dev/mem` enables kernel memory manipulation and privilege escalation.

**Impact**: Kernel exploitation, host process manipulation, complete system compromise

**Mitigation**: Run containers with `--cap-drop=ALL`, never use `--privileged` unless absolutely necessary

### Environment Variable Exposure (HIGH)

**Description**: Sensitive credentials in environment variables can be extracted for lateral movement.

**Impact**: Access to cloud credentials, database passwords, API keys

**Mitigation**: Use secrets management (Vault, AWS Secrets Manager), avoid environment variables for secrets

### Cgroup Escape (MEDIUM)

**Description**: Writable cgroup paths allow modification of resource limits.

**Impact**: Bypass memory/CPU constraints, potential DoS

**Mitigation**: Mount cgroups read-only, use AppArmor or SELinux

## Command Line Options

```
usage: container_detection_remote.py [-h] [--local] [--remote HOST] 
                                      [-u USER] [-p PORT] [-k FILE] 
                                      [--exploit NAME] [--all-exploits] 
                                      [-v] [--output FILE] [--no-color]

optional arguments:
  -h, --help            show this help message and exit
  --local               Run local container detection checks
  --remote HOST         Target remote host/IP for detection (requires SSH access)
  -u USER, --user USER  SSH username (default: root)
  -p PORT, --port PORT  SSH port (default: 22)
  -k FILE, --key FILE   SSH private key file
  --exploit NAME        Run specific exploit POC
  --all-exploits        Run all available exploits
  -v, --verbose         Enable verbose output
  -o FILE, --output FILE
                        Export results to JSON file
  --no-color            Disable colored output
```

## SSH Requirements for Remote Scanning

### Prerequisites

- SSH access to target system
- One of:
  - Root password authentication
  - SSH key-based authentication
  - Non-root user with sudo (for some checks)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Legal Notice

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any system. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse or damage caused by this tool.

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Container Escape Research](https://www.blackhat.com/us-21/briefings/schedule/index.html)

## Authors

- Security Research Team

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review the verbose output (`-v` flag)

## Changelog

### v1.0.0 (2025-12-01)
- Initial release
- Local and remote container detection
- 6 POC exploits
- SSH key and password authentication
- JSON export functionality
- Comprehensive reporting

---

**Remember**: Always use this tool responsibly and legally. Obtain proper authorization before testing any systems you don't own.
