from flask import Flask, request, jsonify, render_template_string
import requests
from functools import wraps
from urllib.parse import urlparse
import ipaddress
import re
import logging
import socket
from typing import Tuple, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security configurations
SECURITY_CONFIG = {
    'allowed_schemes': {'http', 'https'},
    'blocked_schemes': {'file', 'gopher', 'phar', 'data', 'dict', 'ftp', 'sftp', 'ldap', 'tftp'},
    'allowed_ports': {80, 443, 8080, 8443},
    'blocked_ports': {22, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017},
    'allowed_domains': None,
    'max_redirects': 2,
    'timeout': 10,
    'max_content_length': 10 * 1024 * 1024,  # 10MB
    'dns_resolution_check': True,  # Enable DNS resolution for domain validation
}


class EnhancedSSRFProtection:
    """Enhanced SSRF protection with IP encoding detection and DNS validation"""
    
    # Services that provide domain bypassing
    BYPASS_SERVICES = {
        'nip.io',
        'sslip.io',
        'localdomain.local',
        'localtest.me',
        'lvh.me',
        'vcap.me',
        'xip.io',
        'somerandom.io',
    }
    
    # Private IP ranges (CIDR notation)
    PRIVATE_IPV4_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12', 
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '0.0.0.0/8'
    ]
    
    PRIVATE_IPV6_RANGES = [
        '::1/128',
        'fc00::/7',
        'fe80::/10',
        '::ffff:0:0/96'
    ]

    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive URL validation with enhanced SSRF protection
        Returns (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            # 1. Scheme validation
            if not parsed.scheme:
                return False, "URL scheme is required"
            
            if parsed.scheme not in SECURITY_CONFIG['allowed_schemes']:
                return False, f"Protocol '{parsed.scheme}://' is not allowed. Only HTTP and HTTPS are permitted."
            
            # 2. Hostname validation
            if not parsed.hostname:
                return False, "Invalid hostname"
            
            # 3. Enhanced IP address detection and validation
            ip_check_result = EnhancedSSRFProtection._check_ip_security(parsed.hostname)
            if not ip_check_result[0]:
                return ip_check_result
            
            # 4. Domain bypass service detection
            if EnhancedSSRFProtection._is_bypass_service(parsed.hostname):
                return False, f"Domain bypass service detected: {parsed.hostname}"
            
            # 5. DNS resolution check (if enabled)
            if SECURITY_CONFIG['dns_resolution_check']:
                dns_result = EnhancedSSRFProtection._check_dns_resolution(parsed.hostname)
                if not dns_result[0]:
                    return dns_result
            
            # 6. Port validation
            if parsed.port and not EnhancedSSRFProtection._is_allowed_port(parsed.port):
                return False, f"Access to port {parsed.port} is not allowed"
            
            # 7. Domain allow list (if configured)
            if SECURITY_CONFIG['allowed_domains'] and not EnhancedSSRFProtection._is_allowed_domain(parsed.hostname):
                return False, f"Domain '{parsed.hostname}' is not in the allow list"
            
            # 8. URL length validation
            if len(url) > 2000:
                return False, "URL length exceeds maximum allowed size"
            
            logger.info(f"✅ URL validation passed: {url}")
            return True, None
            
        except Exception as e:
            logger.warning(f"❌ URL validation error: {str(e)}")
            return False, f"URL validation error: {str(e)}"
    
    @staticmethod
    def _check_ip_security(host: str) -> Tuple[bool, Optional[str]]:
        """Comprehensive IP security check with encoding detection"""
        
        # Try to detect and normalize encoded IP addresses
        normalized_ip = EnhancedSSRFProtection._normalize_encoded_ip(host)
        
        if normalized_ip:
            # Check if normalized IP is private
            if EnhancedSSRFProtection._is_private_ip(normalized_ip):
                return False, f"Encoded private IP address detected: {host} -> {normalized_ip}"
        
        # Check if it's a direct IP address
        try:
            ip_obj = ipaddress.ip_address(host)
            if EnhancedSSRFProtection._is_private_ip(str(ip_obj)):
                return False, f"Private IP address blocked: {host}"
            return True, None
        except ValueError:
            pass
        
        # Check for IP in domain (like 127.0.0.1.nip.io)
        ip_from_domain = EnhancedSSRFProtection._extract_ip_from_domain(host)
        if ip_from_domain:
            if EnhancedSSRFProtection._is_private_ip(ip_from_domain):
                return False, f"Private IP in domain detected: {host} -> {ip_from_domain}"
        
        return True, None
    
    @staticmethod
    def _normalize_encoded_ip(host: str) -> Optional[str]:
        """
        Detect and normalize various IP encodings:
        - Hexadecimal: 0x7f.0.0.1, 0x7f000001
        - Decimal: 2130706433
        - Octal: 0177.0.0.1, 0377.0377.0377.0377
        - Mixed encodings
        """
        
        # Handle dotted hexadecimal (0x7f.0x0.0x0.0x1)
        if '0x' in host and '.' in host:
            try:
                parts = host.split('.')
                if len(parts) == 4:
                    decimal_parts = []
                    for part in parts:
                        if part.startswith('0x'):
                            decimal_parts.append(str(int(part, 16)))
                        else:
                            decimal_parts.append(part)
                    normalized = '.'.join(decimal_parts)
                    ipaddress.ip_address(normalized)
                    return normalized
            except:
                pass
        
        # Handle dotted octal (0177.0.0.1)
        if host.replace('.', '').replace('0', '').isdigit():
            try:
                parts = host.split('.')
                if len(parts) == 4:
                    decimal_parts = [int(part, 0) for part in parts]  # 0 = auto-detect base
                    normalized = '.'.join(str(part) for part in decimal_parts)
                    ipaddress.ip_address(normalized)
                    return normalized
            except:
                pass
        
        # Handle single decimal (2130706433)
        if host.isdigit():
            try:
                ip_int = int(host)
                if 0 <= ip_int <= 0xFFFFFFFF:
                    ip = ipaddress.IPv4Address(ip_int)
                    return str(ip)
            except:
                pass
        
        # Handle single hexadecimal (0x7f000001)
        if host.startswith('0x'):
            try:
                ip_int = int(host, 16)
                if 0 <= ip_int <= 0xFFFFFFFF:
                    ip = ipaddress.IPv4Address(ip_int)
                    return str(ip)
            except:
                pass
        
        # Handle IPv6 encoded formats
        try:
            # Remove brackets for IPv6
            clean_host = host.strip('[]')
            ipaddress.IPv6Address(clean_host)
            return clean_host
        except:
            pass
        
        return None
    
    @staticmethod
    def _extract_ip_from_domain(host: str) -> Optional[str]:
        """Extract IP address from domains like 127.0.0.1.nip.io"""
        
        # Common patterns for IP in domain
        ip_patterns = [
            r'^(\d+\.\d+\.\d+\.\d+)\.',  # IPv4 at start
            r'\.(\d+\.\d+\.\d+\.\d+)$',  # IPv4 at end
            r'^([0-9a-f:]+)\.',          # IPv6 at start
            r'\.([0-9a-f:]+)$',          # IPv6 at end
        ]
        
        for pattern in ip_patterns:
            match = re.search(pattern, host, re.IGNORECASE)
            if match:
                ip_candidate = match.group(1)
                try:
                    # Validate it's a real IP
                    ipaddress.ip_address(ip_candidate)
                    return ip_candidate
                except ValueError:
                    continue
        
        return None
    
    @staticmethod
    def _is_bypass_service(host: str) -> bool:
        """Check if domain uses bypass services like nip.io"""
        host_lower = host.lower()
        
        for service in EnhancedSSRFProtection.BYPASS_SERVICES:
            if host_lower.endswith('.' + service):
                return True
        
        # Check for patterns like 127-0-0-1.nip.io
        for service in EnhancedSSRFProtection.BYPASS_SERVICES:
            if service in host_lower:
                # Check if it contains IP-like patterns
                ip_patterns = [
                    r'\d+-\d+-\d+-\d+',  # 127-0-0-1
                    r'\d+\.\d+\.\d+\.\d+',  # 127.0.0.1
                    r'0x[0-9a-f]+',  # Hexadecimal
                ]
                
                for pattern in ip_patterns:
                    if re.search(pattern, host_lower):
                        return True
        
        return False
    
    @staticmethod
    def _check_dns_resolution(host: str) -> Tuple[bool, Optional[str]]:
        """Check DNS resolution for private IP detection"""
        try:
            # Resolve hostname to IP addresses
            ips = socket.getaddrinfo(host, None)
            resolved_ips = []
            
            for family, _, _, _, sockaddr in ips:
                if family == socket.AF_INET:  # IPv4
                    ip = sockaddr[0]
                    resolved_ips.append(ip)
                elif family == socket.AF_INET6:  # IPv6
                    ip = sockaddr[0]
                    resolved_ips.append(ip)
            
            # Check all resolved IPs
            for ip in resolved_ips:
                if EnhancedSSRFProtection._is_private_ip(ip):
                    return False, f"DNS resolution reveals private IP: {host} -> {ip}"
            
            return True, None
            
        except socket.gaierror:
            # DNS resolution failed - be conservative
            return False, f"DNS resolution failed for: {host}"
        except Exception as e:
            logger.warning(f"DNS check error for {host}: {str(e)}")
            return False, f"DNS check failed: {str(e)}"
    
    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if IP is in private ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Check IPv4 private ranges
            if ip.version == 4:
                for range_cidr in EnhancedSSRFProtection.PRIVATE_IPV4_RANGES:
                    if ip in ipaddress.IPv4Network(range_cidr, strict=False):
                        return True
            
            # Check IPv6 private ranges
            if ip.version == 6:
                for range_cidr in EnhancedSSRFProtection.PRIVATE_IPV6_RANGES:
                    if ip in ipaddress.IPv6Network(range_cidr, strict=False):
                        return True
            
            return False
            
        except ValueError:
            return False
    
    @staticmethod
    def _is_allowed_port(port: int) -> bool:
        """Check if port is allowed"""
        return port in SECURITY_CONFIG['allowed_ports']
    
    @staticmethod
    def _is_allowed_domain(domain: str) -> bool:
        """Check if domain is in allow list"""
        if not SECURITY_CONFIG['allowed_domains']:
            return True
        return domain in SECURITY_CONFIG['allowed_domains']

def ssrf_protected(f):
    """
    Decorator for SSRF-protected endpoints using enhanced protection
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        url = None
        
        # Try to get URL from different sources
        if request.args.get('url'):
            url = request.args.get('url')
        elif request.form and request.form.get('url'):
            url = request.form.get('url')
        elif request.json and request.json.get('url'):
            url = request.json.get('url')
        elif request.get_data():
            try:
                raw_data = request.get_data(as_text=True)
                if 'url=' in raw_data:
                    import urllib.parse
                    parsed = urllib.parse.parse_qs(raw_data)
                    if 'url' in parsed:
                        url = parsed['url'][0]
            except:
                pass
        
        if not url:
            return jsonify({
                'error': 'URL parameter is required',
                'status': 'blocked',
                'usage': 'Use ?url= parameter in GET or send URL in POST data'
            }), 400
        
        # Validate URL with enhanced protection
        is_valid, error_message = EnhancedSSRFProtection.validate_url(url)
        if not is_valid:
            logger.warning(f"🚨 SSRF attempt blocked: {url} - {error_message}")
            return jsonify({
                'error': error_message,
                'status': 'blocked',
                'security': 'Enhanced SSRF protection activated'
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/get')
@ssrf_protected
def secure_proxy():
    """
    ✅ SECURE: Enhanced SSRF-protected proxy endpoint
    """
    url = request.args.get('url')
    
    try:
        response = requests.get(
            url,
            timeout=SECURITY_CONFIG['timeout'],
            allow_redirects=True,
            verify=True
        )
        
        content_length = len(response.content)
        if content_length > SECURITY_CONFIG['max_content_length']:
            return jsonify({
                'error': f'Response too large ({content_length} bytes)',
                'max_allowed': SECURITY_CONFIG['max_content_length']
            }), 413
        
        return jsonify({
            'status': 'success',
            'url': url,
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type'),
            'content_length': content_length,
            'content_preview': response.text[:1000] + '...' if len(response.text) > 1000 else response.text,
            'security': 'Enhanced SSRF protection enabled'
        })
        
    except requests.exceptions.Timeout:
        return jsonify({
            'error': f'Request timeout ({SECURITY_CONFIG["timeout"]}s)',
            'status': 'blocked'
        }), 408
        
    except requests.exceptions.TooManyRedirects:
        return jsonify({
            'error': f'Too many redirects',
            'status': 'blocked'
        }), 508
        
    except requests.exceptions.SSLError:
        return jsonify({
            'error': 'SSL certificate verification failed',
            'status': 'blocked'
        }), 495
        
    except Exception as e:
        logger.error(f"Request failed: {str(e)}")
        return jsonify({
            'error': f'Request failed: {str(e)}',
            'status': 'error'
        }), 500

@app.route('/security-test')
def security_test():
    """Endpoint to test enhanced SSRF protection scenarios"""
    test_cases = [
        {
            'name': 'Allowed HTTPS URL',
            'url': 'https://httpbin.org/json',
            'expected': 'allowed'
        },
        {
            'name': 'Blocked File Protocol',
            'url': 'file:///etc/passwd',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Localhost',
            'url': 'http://localhost/admin',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Hexadecimal IP',
            'url': 'http://0x7f.0.0.1/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Decimal IP',
            'url': 'http://2130706433/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Octal IP',
            'url': 'http://0177.0.0.1/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked NIP.IO Service',
            'url': 'http://127.0.0.1.nip.io/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Mixed Encoding',
            'url': 'http://0x7f.0.0.0x1/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked IPv6 Localhost',
            'url': 'http://[::1]/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Private IPv4',
            'url': 'http://192.168.1.1/',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Metadata Service',
            'url': 'http://169.254.169.254/',
            'expected': 'blocked'
        },
    ]
    
    results = []
    for test in test_cases:
        is_valid, error = EnhancedSSRFProtection.validate_url(test['url'])
        result = {
            'test_name': test['name'],
            'url': test['url'],
            'expected': test['expected'],
            'actual': 'allowed' if is_valid else 'blocked',
            'error': error if not is_valid else None,
            'passed': (is_valid and test['expected'] == 'allowed') or (not is_valid and test['expected'] == 'blocked')
        }
        results.append(result)
    
    return jsonify({
        'security_test': 'Enhanced SSRF Protection Validation',
        'results': results,
        'summary': {
            'total_tests': len(results),
            'passed_tests': sum(1 for r in results if r['passed']),
            'failed_tests': sum(1 for r in results if not r['passed'])
        }
    })

@app.route('/validate-url')
def validate_url_endpoint():
    """Enhanced URL validation endpoint"""
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    is_valid, error_message = EnhancedSSRFProtection.validate_url(url)
    
    # Get detailed security analysis
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    security_analysis = {
        'scheme_validation': parsed.scheme in SECURITY_CONFIG['allowed_schemes'] if parsed.scheme else False,
        'ip_encoding_detected': EnhancedSSRFProtection._normalize_encoded_ip(hostname) if hostname else False,
        'bypass_service_detected': EnhancedSSRFProtection._is_bypass_service(hostname) if hostname else False,
        'private_ip_detected': False,
        'dns_resolution_checked': False
    }
    
    if hostname:
        normalized_ip = EnhancedSSRFProtection._normalize_encoded_ip(hostname)
        if normalized_ip:
            security_analysis['private_ip_detected'] = EnhancedSSRFProtection._is_private_ip(normalized_ip)
        else:
            security_analysis['private_ip_detected'] = EnhancedSSRFProtection._is_private_ip(hostname)
        
        if SECURITY_CONFIG['dns_resolution_check']:
            dns_valid, _ = EnhancedSSRFProtection._check_dns_resolution(hostname)
            security_analysis['dns_resolution_checked'] = dns_valid
    
    return jsonify({
        'url': url,
        'is_valid': is_valid,
        'error_message': error_message,
        'security_analysis': security_analysis
    })

if __name__ == '__main__':
    print("🛡️ Starting ENHANCED SECURE SSRF-Protected Application...")
    print("✅ Protected endpoints:")
    print("   - /get?url=https://example.com")
    print("   - /security-test (Enhanced SSRF protection tests)")
    print("   - /validate-url?url=... (Enhanced URL validation)")
    print()
    print("🔒 Enhanced Security Features:")
    print("   - Hexadecimal/Decimal/Octal IP encoding detection")
    print("   - NIP.IO and domain bypass service blocking")
    print("   - DNS resolution validation")
    print("   - IPv4/IPv6 private range blocking")
    print("   - Protocol whitelisting (HTTP/HTTPS only)")
    print("   - Port restrictions")
    print()
    print("🌐 Access the enhanced secure interface at: http://localhost:5000")
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=False)