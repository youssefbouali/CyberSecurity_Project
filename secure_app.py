from flask import Flask, request, jsonify, render_template_string
import requests
import logging

# Import the enhanced SSRF protection module
from ssrfprotector import EnhancedSSRFProtection, ssrf_protector, ssrf_protect_url, SECURITY_CONFIG

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# HTML interface for testing (same as before)
HTML_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>URL Fetcher</title>
    <style>
        /* ... your existing styles ... */
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 URL Fetcher</h1>
            <p>Enter any URL to fetch its content</p>
        </div>

        <form id="urlForm" action="/get" method="get">
            <div class="form-group">
                <input type="text" 
                       id="url" 
                       name="url" 
                       placeholder="Enter URL (e.g., file:///myfolder/myfile.txt, http://example.com)" 
                       required>
            </div>
            <button type="submit">Fetch URL Content</button>
        </form>

        <div class="examples">
            <h3>Quick Examples:</h3>
            <div class="example-links">
                <a href="#" class="example-link" onclick="setUrl('file:///myfolder/myfile.txt')">📁 Local File: file:///myfolder/myfile.txt</a>
                <a href="#" class="example-link" onclick="setUrl('http://httpbin.org/json')">🌐 HTTP API: http://httpbin.org/json</a>
                <a href="#" class="example-link" onclick="setUrl('gopher://example.com:6379/_INFO')">📦 Gopher: gopher://example.com:6379</a>
                <a href="#" class="example-link" onclick="setUrl('data:text/html,<h1>Test</h1>')">📄 Data URI: data:text/html</a>
                <a href="#" class="example-link" onclick="setUrl('phar:///test.phar')">📦 Phar: phar:///test.phar</a>
            </div>
        </div>

        <div class="loading" id="loading">
            <div class="loading-spinner"></div>
            <p>Fetching URL content...</p>
        </div>

        <div class="results" id="results">
            <h3>Results:</h3>
            <pre id="resultOutput"></pre>
        </div>
    </div>

    <script>
        function setUrl(url) {
            document.getElementById('url').value = url;
        }

        document.getElementById('urlForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const url = document.getElementById('url').value;
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const resultOutput = document.getElementById('resultOutput');
            
            // Show loading
            loading.style.display = 'block';
            results.style.display = 'none';
            
            // Fetch the URL
            fetch(`/get?url=${encodeURIComponent(url)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.text();
                })
                .then(data => {
                    resultOutput.textContent = data;
                    results.style.display = 'block';
                })
                .catch(error => {
                    resultOutput.textContent = 'Error: ' + error.message;
                    results.style.display = 'block';
                })
                .finally(() => {
                    loading.style.display = 'none';
                });
        });

        // Focus on input when page loads
        document.getElementById('url').focus();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main interface for testing SSRF vulnerabilities"""
    return render_template_string(HTML_INTERFACE)

# Using the default parameter name "url"
@app.route('/get')
@ssrf_protector("url")  # Explicitly specifying the parameter name
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

# Example with different parameter name
@app.route('/fetch')
@ssrf_protector("target")  # Using "target" as parameter name
def fetch_with_custom_param():
    """
    Example endpoint using a custom parameter name
    """
    target_url = request.args.get('target')
    
    try:
        response = requests.get(target_url, timeout=SECURITY_CONFIG['timeout'])
        return jsonify({
            'status': 'success',
            'target_url': target_url,
            'status_code': response.status_code
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Example with backward compatibility
@app.route('/legacy-get')
@ssrf_protect_url  # Using the backward-compatible decorator
def legacy_proxy():
    """
    Backward compatible endpoint using the old decorator style
    """
    url = request.args.get('url')
    return jsonify({'status': 'success', 'url': url})

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
        # ... rest of your test cases
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
    print("   - /fetch?target=https://example.com")
    print("   - /legacy-get?url=https://example.com")
    print("   - /security-test (Enhanced SSRF protection tests)")
    print("   - /validate-url?url=... (Enhanced URL validation)")
    print()
    print("🔒 Enhanced Security Features:")
    print("   - Configurable parameter names")
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