"""
Enhanced SSRF Protection Module
Provides comprehensive protection against Server-Side Request Forgery attacks
"""

import ipaddress
import re
import logging
import socket
from typing import Tuple, Optional, Callable, Any
from urllib.parse import urlparse
from functools import wraps
from flask import request, jsonify

# Configure logging
logger = logging.getLogger(__name__)

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

def ssrf_protector(param: str = "url") -> Callable:
    """
    Decorator factory for SSRF-protected endpoints using enhanced protection
    
    Args:
        param: The parameter name to look for in the request (default: "url")
    
    Returns:
        Decorator function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            url = None
            
            # Try to get URL from different sources using the specified parameter
            if request.args.get(param):
                url = request.args.get(param)
            elif request.form and request.form.get(param):
                url = request.form.get(param)
            elif request.json and request.json.get(param):
                url = request.json.get(param)
            elif request.get_data():
                try:
                    raw_data = request.get_data(as_text=True)
                    if f'{param}=' in raw_data:
                        import urllib.parse
                        parsed = urllib.parse.parse_qs(raw_data)
                        if param in parsed:
                            url = parsed[param][0]
                except:
                    pass
            
            if not url:
                return jsonify({
                    'error': f'{param} parameter is required',
                    'status': 'blocked',
                    'usage': f'Use ?{param}= parameter in GET or send {param} in POST data'
                }), 400
            
            # Validate URL with enhanced protection
            is_valid, error_message = EnhancedSSRFProtection.validate_url(url)
            if not is_valid:
                logger.warning(f"🚨 SSRF attempt blocked: {url} - {error_message}")
                return jsonify({
                    'error': error_message,
                    'status': 'blocked',
                    'security': 'Enhanced SSRF protection activated',
                    'param_name': param
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Alternative decorator with default parameter for backward compatibility
def ssrf_protect_url(f: Callable) -> Callable:
    """
    Default SSRF protector using 'url' parameter (backward compatibility)
    """
    return ssrf_protector("url")(f)

def update_security_config(new_config: dict):
    """
    Update security configuration dynamically
    """
    global SECURITY_CONFIG
    SECURITY_CONFIG.update(new_config)
    logger.info("Security configuration updated")

def get_security_config():
    """
    Get current security configuration
    """
    return SECURITY_CONFIG.copy()