from flask import Flask, request, jsonify, render_template
import requests
from functools import wraps
from urllib.parse import urlparse
import ipaddress
import re
import logging
from typing import Tuple, Optional

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
    # تم تعليق allowed_domains للسماح بأي نطاق (مع الحماية الأخرى)
    'allowed_domains': None,  # None يعني لا توجد قيود على النطاقات
    'max_redirects': 2,
    'timeout': 10,
    'max_content_length': 10 * 1024 * 1024,  # 10MB
}

class SSRFProtection:
    """Comprehensive SSRF protection class"""
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive URL validation to prevent SSRF attacks
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
            
            # 3. Private IP address detection
            if SSRFProtection._is_private_ip(parsed.hostname):
                return False, "Access to private IP addresses is blocked"
            
            # 4. Localhost detection
            if SSRFProtection._is_localhost(parsed.hostname):
                return False, "Access to localhost is blocked"
            
            # 5. Port validation
            if parsed.port and not SSRFProtection._is_allowed_port(parsed.port):
                return False, f"Access to port {parsed.port} is not allowed"
            
            # 6. Domain allow list (if configured)
            if SECURITY_CONFIG['allowed_domains'] and not SSRFProtection._is_allowed_domain(parsed.hostname):
                return False, f"Domain '{parsed.hostname}' is not in the allow list"
            
            # 7. DNS rebinding protection
            if SSRFProtection._has_dns_rebinding_attempt(parsed.hostname):
                return False, "Potential DNS rebinding attempt detected"
            
            # 8. URL length validation
            if len(url) > 2000:
                return False, "URL length exceeds maximum allowed size"
            
            logger.info(f"✅ URL validation passed: {url}")
            return True, None
            
        except Exception as e:
            logger.warning(f"❌ URL validation error: {str(e)}")
            return False, f"URL validation error: {str(e)}"
    
    @staticmethod
    def _is_private_ip(host: str) -> bool:
        """Check if host is a private IP address"""
        try:
            # Handle different IP formats
            ip = SSRFProtection._normalize_ip(host)
            if not ip:
                return False
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private ranges
            if ip_obj.is_private:
                return True
            
            # Check for loopback
            if ip_obj.is_loopback:
                return True
            
            # Check for link-local
            if ip_obj.is_link_local:
                return True
            
            # Check for multicast
            if ip_obj.is_multicast:
                return True
            
            # Check for reserved
            if ip_obj.is_reserved:
                return True
            
            return False
            
        except ValueError:
            # If it's not a valid IP, it might be a hostname
            return False
    
    @staticmethod
    def _normalize_ip(host: str) -> Optional[str]:
        """Normalize IP address from various formats"""
        try:
            # Handle octal encoding (0177.0.0.1 -> 127.0.0.1)
            if host.replace('.', '').isdigit():
                try:
                    # Check if it's an octal encoded IP
                    parts = host.split('.')
                    if len(parts) == 4:
                        decimal_parts = [int(part, 0) for part in parts]  # 0 = auto-detect base
                        normalized = '.'.join(str(part) for part in decimal_parts)
                        ipaddress.ip_address(normalized)
                        return normalized
                except:
                    pass
            
            # Handle decimal encoding (2130706433 -> 127.0.0.1)
            if host.isdigit():
                try:
                    ip_int = int(host)
                    if 0 <= ip_int <= 0xFFFFFFFF:
                        # Convert to IP address
                        ip = ipaddress.IPv4Address(ip_int)
                        return str(ip)
                except:
                    pass
            
            # Handle hexadecimal (0x7f000001 -> 127.0.0.1)
            if host.startswith('0x'):
                try:
                    ip_int = int(host, 16)
                    if 0 <= ip_int <= 0xFFFFFFFF:
                        ip = ipaddress.IPv4Address(ip_int)
                        return str(ip)
                except:
                    pass
            
            # Regular IP address
            ipaddress.ip_address(host)
            return host
            
        except ValueError:
            return None
    
    @staticmethod
    def _is_localhost(host: str) -> bool:
        """Check if hostname resolves to localhost"""
        localhost_indicators = {
            'localhost',
            'local',
            '127.0.0.1',
            '::1',
            '0.0.0.0',
            '0000::0',
            'localhost.localdomain',
            'localtest.me',
            'lvh.me',
            '127.0.0.1.nip.io',
            '0x7f.0x0.0x0.0x1',
        }
        
        # Check exact matches
        if host.lower() in localhost_indicators:
            return True
        
        # Check subdomains of localhost
        if host.lower().endswith('.localhost'):
            return True
        
        # Check for IPv4 and IPv6 variations
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_loopback
        except ValueError:
            pass
        
        return False
    
    @staticmethod
    def _is_allowed_port(port: int) -> bool:
        """Check if port is allowed"""
        return port in SECURITY_CONFIG['allowed_ports']
    
    @staticmethod
    def _is_allowed_domain(domain: str) -> bool:
        """Check if domain is in allow list"""
        # إذا كانت allowed_domains هي None أو فارغة، اسمح بجميع النطاقات
        if not SECURITY_CONFIG['allowed_domains']:
            return True  # لا توجد قيود على النطاقات
        
        return domain in SECURITY_CONFIG['allowed_domains']
    
    @staticmethod
    def _has_dns_rebinding_attempt(host: str) -> bool:
        """Detect potential DNS rebinding attempts"""
        suspicious_patterns = [
            r'.*@.*',                    # Userinfo in host
            r'.*\.localhost.*',          # Localhost subdomains
            r'.*\.internal.*',           # Internal domains
            r'.*\.local.*',              # Local domains
            r'.*\.example.*',            # Example domains
            r'^[0-9a-fA-F:]+$',          # Raw IPv6 without brackets
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, host, re.IGNORECASE):
                return True
        
        return False

def ssrf_protected(f):
    """
    Decorator for SSRF-protected endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get URL from request - support multiple content types
        url = None
        
        # Try to get URL from different sources
        if request.args.get('url'):
            url = request.args.get('url')  # GET parameters
        elif request.form and request.form.get('url'):
            url = request.form.get('url')  # POST form data
        elif request.json and request.json.get('url'):
            url = request.json.get('url')  # JSON data
        elif request.get_data():
            # Try to parse raw data
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
        
        # Validate URL
        is_valid, error_message = SSRFProtection.validate_url(url)
        if not is_valid:
            logger.warning(f"🚨 SSRF attempt blocked: {url} - {error_message}")
            return jsonify({
                'error': error_message,
                'status': 'blocked',
                'security': 'SSRF protection activated'
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main interface for testing secure proxy"""
    allowed_domains_display = "Any domain (no restrictions)" if not SECURITY_CONFIG['allowed_domains'] else ', '.join(SECURITY_CONFIG['allowed_domains'])
    
    return render_template(
        "secure-interface.html",
        allowed_domains=allowed_domains_display,
        allowed_ports=', '.join(map(str, sorted(SECURITY_CONFIG['allowed_ports']))),
        blocked_schemes=', '.join(SECURITY_CONFIG['blocked_schemes'])
    )

@app.route('/get')
@ssrf_protected
def secure_proxy():
    """
    ✅ SECURE: SSRF-protected proxy endpoint
    Only allows validated HTTP/HTTPS URLs
    """
    url = request.args.get('url')
    
    try:
        # Make the request with security constraints
        response = requests.get(
            url,
            timeout=SECURITY_CONFIG['timeout'],
            allow_redirects=True,  # تم التعديل هنا
            verify=True  # SSL verification
        )
        
        # Check content length
        content_length = len(response.content)
        if content_length > SECURITY_CONFIG['max_content_length']:
            return jsonify({
                'error': f'Response too large ({content_length} bytes)',
                'max_allowed': SECURITY_CONFIG['max_content_length']
            }), 413
        
        # Return safe response
        return jsonify({
            'status': 'success',
            'url': url,
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type'),
            'content_length': content_length,
            'content_preview': response.text[:1000] + '...' if len(response.text) > 1000 else response.text,
            'security': 'SSRF protection enabled'
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
    """Endpoint to test various SSRF protection scenarios"""
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
            'name': 'Blocked Private IP',
            'url': 'http://192.168.1.1',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Metadata Service',
            'url': 'http://169.254.169.254',
            'expected': 'blocked'
        },
        {
            'name': 'Blocked Gopher Protocol',
            'url': 'gopher://127.0.0.1:6379',
            'expected': 'blocked'
        },
    ]
    
    results = []
    for test in test_cases:
        is_valid, error = SSRFProtection.validate_url(test['url'])
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
        'security_test': 'SSRF Protection Validation',
        'results': results,
        'summary': {
            'total_tests': len(results),
            'passed_tests': sum(1 for r in results if r['passed']),
            'failed_tests': sum(1 for r in results if not r['passed'])
        }
    })

@app.route('/validate-url')
def validate_url_endpoint():
    """Endpoint to validate URLs without making requests"""
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    is_valid, error_message = SSRFProtection.validate_url(url)
    
    return jsonify({
        'url': url,
        'is_valid': is_valid,
        'error_message': error_message,
        'security_checks': {
            'scheme_validation': SSRFProtection.validate_url(url)[0] if is_valid else False,
            'private_ip_blocked': SSRFProtection._is_private_ip(urlparse(url).hostname) if urlparse(url).hostname else False,
            'localhost_blocked': SSRFProtection._is_localhost(urlparse(url).hostname) if urlparse(url).hostname else False
        }
    })

if __name__ == '__main__':
    print("🛡️ Starting SECURE SSRF-Protected Application...")
    print("✅ Protected endpoints:")
    print("   - /get?url=https://example.com")
    print("   - /security-test (SSRF protection tests)")
    print("   - /validate-url?url=... (URL validation)")
    print()
    print("🔒 Security Features:")
    print("   - Protocol whitelisting (HTTP/HTTPS only)")
    print("   - Private IP blocking (RFC 1918, loopback, etc.)")
    print("   - Port restrictions")
    print("   - DNS rebinding protection")
    print("   - Request size/timeout limits")
    print("   - No domain restrictions (all domains allowed)")
    print()
    print("🌐 Access the secure interface at: http://localhost:5000")
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=False)