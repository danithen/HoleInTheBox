#!/usr/bin/env python3
"""
Container Environment Detection Tool - Remote & Local CLI with POC Exploits
Educational tool for authorized container security assessment.
For Linux systems only.

WARNING: This tool includes proof-of-concept exploits for educational purposes.
Only use on systems you own or have explicit written permission to test.
"""

import os
import sys
import subprocess
import argparse
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


# ============================================
# ANSI COLOR CODES
# ============================================
class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    @staticmethod
    def disable():
        """Disable colors if not supported"""
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')


def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.RESET} {text}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}✗{Colors.RESET} {text}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {text}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ{Colors.RESET} {text}")


def print_muted(text: str):
    """Print muted message"""
    print(f"{Colors.GRAY}{text}{Colors.RESET}")


def print_exploit(text: str):
    """Print exploit message"""
    print(f"{Colors.RED}{Colors.BOLD}[EXPLOIT]{Colors.RESET} {text}")


# ============================================
# REMOTE SSH EXECUTOR
# ============================================
class RemoteExecutor:
    """Execute commands on remote systems via SSH"""
    
    def __init__(self, host: str, user: str = "root", port: int = 22, key_file: Optional[str] = None, verbose: bool = False):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.verbose = verbose
    
    def execute(self, command: str) -> Tuple[bool, str, str]:
        """Execute command on remote host via SSH"""
        ssh_cmd = ['ssh']
        
        if self.key_file:
            ssh_cmd.extend(['-i', self.key_file])
        
        ssh_cmd.extend(['-p', str(self.port)])
        ssh_cmd.append(f'{self.user}@{self.host}')
        ssh_cmd.append(command)
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def read_remote_file(self, file_path: str) -> Tuple[bool, str]:
        """Read a file from remote system"""
        success, output, error = self.execute(f'cat {file_path} 2>/dev/null')
        if success:
            return True, output
        return False, error
    
    def check_remote_access(self) -> bool:
        """Test if SSH access is available"""
        success, _, _ = self.execute('echo "test"')
        return success


# ============================================
# VULNERABILITY EXPLOITS (POC)
# ============================================
class VulnerabilityExploits:
    """Proof-of-concept exploits for found vulnerabilities"""
    
    def __init__(self, remote_executor: Optional[RemoteExecutor] = None):
        self.remote = remote_executor
    
    def poc_docker_socket_escape(self) -> bool:
        """POC: Escape from container via Docker socket"""
        print_exploit("Attempting Docker socket escape...")
        
        socket_paths = ['/var/run/docker.sock', '/run/docker.sock']
        
        for socket_path in socket_paths:
            if self.remote:
                success, output, _ = self.remote.execute(f'test -r {socket_path} && echo "exists"')
                if not success or "exists" not in output:
                    continue
            else:
                if not os.path.exists(socket_path) or not os.access(socket_path, os.R_OK):
                    continue
            
            print_info(f"Found accessible Docker socket: {socket_path}")
            print_muted("POC: Would execute the following command:")
            print(f"{Colors.CYAN}docker -H unix://{socket_path} run -it -v /:/host ubuntu bash{Colors.RESET}")
            print_warning("This would mount the host filesystem inside a new container")
            print_muted("Allowing full host filesystem access and potential privilege escalation")
            return True
        
        print_error("Docker socket not accessible")
        return False
    
    def poc_privileged_container_escape(self) -> bool:
        """POC: Escape from privileged container via /dev/mem"""
        print_exploit("Attempting privileged container escape...")
        
        if self.remote:
            success, output, _ = self.remote.execute('test -r /dev/mem && echo "accessible"')
            if not success or "accessible" not in output:
                print_error("/dev/mem not accessible (not in privileged container)")
                return False
        else:
            if not os.path.exists('/dev/mem'):
                print_error("/dev/mem not accessible (not in privileged container)")
                return False
        
        print_success("/dev/mem is accessible!")
        print_muted("POC: Privileged container can read/write host memory")
        print_warning("This allows kernel memory manipulation and privilege escalation")
        return True
    
    def poc_env_variable_escape(self) -> bool:
        """POC: Extract sensitive environment variables"""
        print_exploit("Attempting environment variable extraction...")
        
        sensitive_vars = [
            'DOCKER_HOST', 'DOCKER_CERT_PATH', 'KUBERNETES_SERVICE',
            'KUBERNETES_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
            'API_KEY', 'DB_PASSWORD', 'SECRET_KEY'
        ]
        
        found_sensitive = []
        
        if self.remote:
            success, env_output, _ = self.remote.execute('env')
            if success:
                for line in env_output.split('\n'):
                    for var in sensitive_vars:
                        if var in line:
                            found_sensitive.append(line.split('=')[0])
                            print_warning(f"Found sensitive env var: {line[:60]}...")
        else:
            for var in sensitive_vars:
                if var in os.environ:
                    found_sensitive.append(var)
                    print_warning(f"Found sensitive env var: {var}={os.environ[var][:20]}...")
        
        if found_sensitive:
            print_success(f"Extracted {len(found_sensitive)} sensitive environment variables")
            print_muted("POC: These could be used for lateral movement or privilege escalation")
            return True
        
        print_info("No obvious sensitive environment variables found")
        return False


# ============================================
# CONTAINER DETECTION
# ============================================
class ContainerDetector:
    """Detects container environments on Linux systems"""
    
    def __init__(self, verbose: bool = False, remote_executor: Optional[RemoteExecutor] = None):
        self.verbose = verbose
        self.remote = remote_executor
        self.results = {
            'is_container': False,
            'container_type': None,
            'detection_methods': [],
            'warnings': [],
            'recommendations': [],
            'positive_checks': [],
            'vulnerabilities': [],
            'timestamp': datetime.now().isoformat(),
            'target': remote_executor.host if remote_executor else 'localhost'
        }
        self.exploits = VulnerabilityExploits(remote_executor=remote_executor)
    
    def _read_file(self, path: str) -> Optional[str]:
        """Read file locally or remotely"""
        if self.remote:
            success, content = self.remote.read_remote_file(path)
            return content if success else None
        else:
            try:
                with open(path, 'r') as f:
                    return f.read()
            except:
                return None
    
    def _file_exists(self, path: str) -> bool:
        """Check if file exists locally or remotely"""
        if self.remote:
            success, _, _ = self.remote.execute(f'test -f {path} && echo "exists"')
            return success
        else:
            return os.path.exists(path)
    
    def _execute_cmd(self, cmd: str) -> Tuple[bool, str]:
        """Execute command locally or remotely"""
        if self.remote:
            success, output, _ = self.remote.execute(cmd)
            return success, output
        else:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                return result.returncode == 0, result.stdout
            except:
                return False, ""
    
    def check_cgroup(self) -> bool:
        """Check if running in container via cgroup"""
        content = self._read_file('/proc/1/cgroup')
        if not content:
            if self.verbose:
                print_muted("  [debug] /proc/1/cgroup not found")
            return False
        
        if 'docker' in content:
            self.results['detection_methods'].append('cgroup analysis (docker)')
            self.results['container_type'] = 'Docker'
            self.results['positive_checks'].append('cgroup')
            return True
        
        if 'lxc' in content:
            self.results['detection_methods'].append('cgroup analysis (lxc)')
            self.results['container_type'] = 'LXC'
            self.results['positive_checks'].append('cgroup')
            return True
        
        if 'kubepods' in content:
            self.results['detection_methods'].append('cgroup analysis (kubernetes)')
            self.results['container_type'] = 'Kubernetes Pod'
            self.results['positive_checks'].append('cgroup')
            return True
        
        if 'systemd' not in content and 'init' not in content:
            self.results['detection_methods'].append('cgroup analysis (generic)')
            self.results['positive_checks'].append('cgroup')
            return True
        
        return False
    
    def check_docker_env(self) -> bool:
        """Check for Docker environment variables"""
        docker_env_vars = ['DOCKER', 'container', 'KUBERNETES_SERVICE', 'MESOS_CONTAINER', 'ECS_CONTAINER']
        
        if self.remote:
            success, env_output, _ = self.remote.execute('env')
            if success:
                for line in env_output.split('\n'):
                    for docker_var in docker_env_vars:
                        if docker_var.lower() in line.lower():
                            self.results['detection_methods'].append(f'environment variable: {line.split("=")[0]}')
                            self.results['positive_checks'].append('docker_env')
                            return True
        else:
            for var in os.environ:
                for docker_var in docker_env_vars:
                    if docker_var.lower() in var.lower():
                        self.results['detection_methods'].append(f'environment variable: {var}')
                        self.results['positive_checks'].append('docker_env')
                        return True
        
        return False
    
    def check_docker_pid(self) -> bool:
        """Check if PID 1 is not typical init/systemd"""
        content = self._read_file('/proc/1/comm')
        if not content:
            if self.verbose:
                print_muted("  [debug] /proc/1/comm not found")
            return False
        
        comm = content.strip()
        if comm not in ['init', 'systemd', 'bash', 'sh', 'python3', 'python']:
            self.results['detection_methods'].append(f'PID 1 process: {comm}')
            self.results['positive_checks'].append('docker_pid')
            return True
        
        return False
    
    def check_mounts(self) -> bool:
        """Check mount points for container indicators"""
        content = self._read_file('/proc/mounts')
        if not content:
            if self.verbose:
                print_muted("  [debug] /proc/mounts not found")
            return False
        
        container_mounts = ['overlay', 'aufs', 'devicemapper', 'docker', 'lxcfs']
        
        for mount_type in container_mounts:
            if mount_type in content:
                self.results['detection_methods'].append(f'mount type: {mount_type}')
                self.results['positive_checks'].append('mounts')
                return True
        
        return False
    
    def check_host_docker_socket(self) -> bool:
        """Check if Docker socket is accessible"""
        socket_paths = ['/var/run/docker.sock', '/run/docker.sock']
        
        for path in socket_paths:
            if self._file_exists(path):
                self.results['warnings'].append(f'Docker socket accessible at {path}')
                self.results['recommendations'].append(f'Secure or remove Docker socket access at {path}')
                self.results['vulnerabilities'].append({
                    'type': 'docker_socket_escape',
                    'severity': 'CRITICAL',
                    'description': 'Docker socket is accessible - enables container escape',
                    'poc': 'docker_socket_escape'
                })
                self.results['positive_checks'].append('docker_socket')
                return True
        
        return False
    
    def check_privileged(self) -> bool:
        """Check for signs of privileged container"""
        if self._file_exists('/dev/mem'):
            self.results['warnings'].append('Container may be privileged (has /dev/mem)')
            self.results['recommendations'].append('Run containers with --cap-drop=ALL and add only needed capabilities')
            self.results['vulnerabilities'].append({
                'type': 'privileged_escape',
                'severity': 'CRITICAL',
                'description': '/dev/mem is accessible - privileged container detected',
                'poc': 'privileged_container_escape'
            })
            self.results['positive_checks'].append('privileged')
            return True
        
        return False
    
    def run_all_checks(self) -> Dict:
        """Run all detection checks"""
        checks = [
            ('cgroup', self.check_cgroup),
            ('docker_env', self.check_docker_env),
            ('docker_pid', self.check_docker_pid),
            ('mounts', self.check_mounts),
            ('docker_socket', self.check_host_docker_socket),
            ('privileged', self.check_privileged),
        ]
        
        if self.verbose:
            print_muted("Running detection checks...\n")
        
        for check_name, check_func in checks:
            try:
                if check_func():
                    if self.verbose:
                        print_success(f"Detected via {check_name}")
            except Exception as e:
                if self.verbose:
                    print_error(f"Check {check_name} failed: {e}")
        
        self.results['is_container'] = len(self.results['positive_checks']) > 0
        
        if not self.results['recommendations']:
            self.results['recommendations'] = [
                'Run containers as non-root users: docker run --user 1000:1000',
                'Drop all capabilities: docker run --cap-drop=ALL',
                'Use read-only filesystems where possible: docker run --read-only',
                'Avoid mounting Docker socket: -v /var/run/docker.sock',
                'Use security profiles: --security-opt=no-new-privileges:true',
                'Limit resources: --memory=256m --cpu-quota=50000',
                'Scan images for vulnerabilities using Trivy or Clair',
                'Use secrets management instead of environment variables',
            ]
        
        return self.results
    
    def generate_report(self) -> None:
        """Generate and display security assessment report"""
        target_info = f" - {self.results['target']}" if self.results['target'] != 'localhost' else ""
        print_header(f"CONTAINER SECURITY ASSESSMENT REPORT{target_info}")
        
        if self.results['is_container']:
            print_success("Running in container environment")
            if self.results['container_type']:
                print_info(f"Container Type: {self.results['container_type']}")
        else:
            print_warning("Not in container (or well-hidden)")
        
        print_muted(f"Timestamp: {self.results['timestamp']}")
        print_muted(f"Target: {self.results['target']}")
        
        if self.results['detection_methods']:
            print(f"\n{Colors.BOLD}Detection Methods:{Colors.RESET}")
            for method in self.results['detection_methods']:
                print_muted(f"  • {method}")
        
        print(f"\n{Colors.BOLD}Detection Summary:{Colors.RESET}")
        print_info(f"Positive Checks: {len(self.results['positive_checks'])}/6")
        
        if self.results['vulnerabilities']:
            print(f"\n{Colors.BOLD}{Colors.RED}VULNERABILITIES FOUND:{Colors.RESET}")
            for vuln in self.results['vulnerabilities']:
                print_exploit(f"[{vuln['severity']}] {vuln['description']}")
        
        if self.results['warnings']:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}⚠ SECURITY WARNINGS:{Colors.RESET}")
            for warning in self.results['warnings']:
                print_warning(warning)
        
        if self.results['recommendations']:
            print(f"\n{Colors.BOLD}{Colors.GREEN}✓ SECURITY RECOMMENDATIONS:{Colors.RESET}")
            for i, rec in enumerate(self.results['recommendations'], 1):
                print_muted(f"  {i}. {rec}")
        
        print_header("")
    
    def run_exploit(self, exploit_name: str) -> bool:
        """Run a specific exploit POC"""
        exploit_map = {
            'docker_socket_escape': self.exploits.poc_docker_socket_escape,
            'privileged_container_escape': self.exploits.poc_privileged_container_escape,
            'env_variable_escape': self.exploits.poc_env_variable_escape,
        }
        
        if exploit_name not in exploit_map:
            print_error(f"Unknown exploit: {exploit_name}")
            return False
        
        print_exploit(f"Running POC for {exploit_name}...\n")
        return exploit_map[exploit_name]()
    
    def run_all_exploits(self) -> None:
        """Run all available exploits"""
        print_header("RUNNING VULNERABILITY EXPLOITS")
        
        exploits = [
            'docker_socket_escape',
            'privileged_container_escape',
            'env_variable_escape',
        ]
        
        for exploit in exploits:
            print()
            self.run_exploit(exploit)
            print()


# ============================================
# MAIN CLI
# ============================================
def main():
    parser = argparse.ArgumentParser(
        description='Container Detection CLI with Remote SSH Support - Educational security assessment tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Local detection
  %(prog)s --local
  %(prog)s --local -v
  
  # Remote detection via SSH
  %(prog)s --remote 192.168.1.100 --user root
  %(prog)s --remote example.com --user ubuntu --key ~/.ssh/id_rsa
  
  # Run exploits
  %(prog)s --local --exploit docker_socket_escape
  %(prog)s --remote 192.168.1.100 --user root --all-exploits
  
  # Export results
  %(prog)s --local --output report.json
  
DISCLAIMER:
  Use only on systems you own or have explicit written permission to test.
  Unauthorized access is illegal. This tool is for educational purposes only.
        """
    )
    
    parser.add_argument(
        '--local',
        action='store_true',
        help='Run local container detection checks'
    )
    parser.add_argument(
        '--remote',
        metavar='HOST',
        help='Target remote host/IP for detection (requires SSH access)'
    )
    parser.add_argument(
        '--user', '-u',
        default='root',
        help='SSH username (default: root)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=22,
        help='SSH port (default: 22)'
    )
    parser.add_argument(
        '--key', '-k',
        metavar='FILE',
        help='SSH private key file'
    )
    parser.add_argument(
        '--exploit',
        metavar='NAME',
        help='Run specific exploit POC'
    )
    parser.add_argument(
        '--all-exploits',
        action='store_true',
        help='Run all available exploits'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--output', '-o',
        metavar='FILE',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    args = parser.parse_args()
    
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}╔{'='*58}╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}║ CONTAINER DETECTION CLI WITH REMOTE SSH SUPPORT        ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}║ Use only on authorized systems                        ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}╚{'='*58}╝{Colors.RESET}\n")
    
    # Determine target
    remote_executor = None
    if args.remote:
        print_info(f"Connecting to {args.user}@{args.remote}:{args.port}...")
        remote_executor = RemoteExecutor(
            host=args.remote,
            user=args.user,
            port=args.port,
            key_file=args.key,
            verbose=args.verbose
        )
        
        if not remote_executor.check_remote_access():
            print_error("Failed to connect to remote host. Check SSH credentials and access.")
            sys.exit(1)
        
        print_success("Connected to remote host!")
    elif not args.local and not args.exploit and not args.all_exploits:
        args.local = True
    
    # Initialize detector
    detector = ContainerDetector(verbose=args.verbose, remote_executor=remote_executor)
    
    # Run detection
    if args.local or args.remote:
        detector.run_all_checks()
        detector.generate_report()
    
    # Run exploits
    if args.all_exploits:
        detector.run_all_exploits()
    elif args.exploit:
        detector.run_exploit(args.exploit)
    
    # Export results
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(detector.results, f, indent=2)
            print_success(f"Results exported to {args.output}")
        except Exception as e:
            print_error(f"Failed to export results: {e}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)
