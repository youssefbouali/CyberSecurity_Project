from flask import Flask, request, jsonify, render_template_string
import requests
import urllib3
from urllib.parse import urlparse
import os

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# HTML interface for testing
HTML_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable SSRF Proxy - Dangerous Protocols</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .card { background: #fff; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #e74c3c; }
        .card.safe { border-left-color: #27ae60; }
        .form-group { margin: 15px 0; }
        input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background: #e74c3c; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button.safe { background: #27ae60; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .protocols { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin: 20px 0; }
        .protocol-card { background: #34495e; color: white; padding: 15px; border-radius: 8px; }
        .danger { background: #e74c3c; }
        .warning { background: #f39c12; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 Vulnerable SSRF Proxy</h1>
        <p><strong>Warning:</strong> This application is intentionally vulnerable to demonstrate SSRF attacks with dangerous protocols.</p>
        
        <div class="protocols">
            <div class="protocol-card danger">
                <h3>📁 file:// Protocol</h3>
                <p>Read local files from the server</p>
                <code>file:///etc/passwd</code>
            </div>
            <div class="protocol-card danger">
                <h3>📦 phar:// Protocol</h3>
                <p>PHP archive deserialization attacks</p>
                <code>phar:///path/to/file.phar</code>
            </div>
            <div class="protocol-card danger">
                <h3>🌐 gopher:// Protocol</h3>
                <p>Exploit internal services (Redis, SMTP)</p>
                <code>gopher://127.0.0.1:6379</code>
            </div>
            <div class="protocol-card warning">
                <h3>📄 data:// Protocol</h3>
                <p>Data URI scheme for XSS and code injection</p>
                <code>data:text/html,&lt;script&gt;</code>
            </div>
            <div class="protocol-card warning">
                <h3>📚 dict:// Protocol</h3>
                <p>Dictionary protocol for service enumeration</p>
                <code>dict://127.0.0.1:11211/stats</code>
            </div>
        </div>

        <div class="card">
            <h2>🔧 Test SSRF Vulnerabilities</h2>
            <form id="ssrfForm">
                <div class="form-group">
                    <label for="url">Enter URL to fetch:</label><br>
                    <input type="text" id="url" name="url" placeholder="file:///etc/passwd" value="file:///etc/passwd">
                    <button type="button" onclick="testSSRF()">Test SSRF</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>🚀 Quick Test Links</h2>
            <div class="form-group">
                <button class="danger" onclick="testProtocol('file:///etc/passwd')">Test file://</button>
                <button class="danger" onclick="testProtocol('file:///c:/windows/system32/drivers/etc/hosts')">Test Windows file://</button>
                <button class="danger" onclick="testProtocol('phar:///etc/passwd')">Test phar://</button>
                <button class="danger" onclick="testProtocol('gopher://127.0.0.1:6379/_INFO')">Test gopher:// Redis</button>
                <button class="warning" onclick="testProtocol('data:text/html,<h1>SSRF Test</h1>')">Test data://</button>
                <button class="warning" onclick="testProtocol('dict://127.0.0.1:11211/stats')">Test dict://</button>
                <button class="safe" onclick="testProtocol('http://httpbin.org/json')">Test Safe HTTP</button>
            </div>
        </div>

        <div id="results" style="display: none;">
            <h2>📊 Results</h2>
            <pre id="resultOutput"></pre>
        </div>

        <div class="card safe">
            <h2>🛡️ Protected Endpoint (For Comparison)</h2>
            <div class="form-group">
                <input type="text" id="safeUrl" placeholder="https://httpbin.org/json" value="https://httpbin.org/json">
                <button class="safe" onclick="testSafeEndpoint()">Test Protected</button>
            </div>
        </div>
    </div>

    <script>
        function testSSRF() {
            const url = document.getElementById('url').value;
            fetch(`/get?url=${encodeURIComponent(url)}`)
                .then(response => response.text())
                .then(data => {
                    document.getElementById('resultOutput').textContent = data;
                    document.getElementById('results').style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('resultOutput').textContent = 'Error: ' + error;
                    document.getElementById('results').style.display = 'block';
                });
        }

        function testProtocol(url) {
            document.getElementById('url').value = url;
            testSSRF();
        }

        function testSafeEndpoint() {
            const url = document.getElementById('safeUrl').value;
            fetch(`/protected-proxy?url=${encodeURIComponent(url)}`)
                .then(response => response.text())
                .then(data => {
                    document.getElementById('resultOutput').textContent = data;
                    document.getElementById('results').style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('resultOutput').textContent = 'Error: ' + error;
                    document.getElementById('results').style.display = 'block';
                });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main interface for testing SSRF vulnerabilities"""
    return render_template_string(HTML_INTERFACE)

@app.route('/get')
def vulnerable_proxy():
    """
    🚨 VULNERABLE: No validation - accepts any protocol
    This demonstrates critical SSRF vulnerability
    """
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    print(f"🚨 VULNERABLE PROXY ACCESSED: {url}")
    
    try:
        # 🚨 CRITICAL VULNERABILITY: No protocol validation!
        # This allows dangerous protocols like file://, gopher://, etc.
        
        if url.startswith('file://'):
            # Handle file protocol - read local files
            return handle_file_protocol(url)
        
        elif url.startswith('phar://'):
            # Handle phar protocol - PHP archive access
            return handle_phar_protocol(url)
        
        elif url.startswith('gopher://'):
            # Handle gopher protocol - internal service exploitation
            return handle_gopher_protocol(url)
        
        elif url.startswith('data:'):
            # Handle data protocol - data URI scheme
            return handle_data_protocol(url)
        
        elif url.startswith('dict://'):
            # Handle dict protocol - dictionary service
            return handle_dict_protocol(url)
        
        else:
            # Handle HTTP/HTTPS and other protocols
            response = requests.get(url, timeout=10, verify=False)
            return response.text
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'url': url,
            'message': 'SSRF attack attempted'
        }), 500

def handle_file_protocol(url):
    """Handle file:// protocol - Local file system access"""
    try:
        # Extract file path from file:// URL
        file_path = url[7:]  # Remove 'file://'
        
        # 🚨 CRITICAL: No path validation!
        # This allows reading any file the server has access to
        
        # Handle Windows paths
        if file_path.startswith('/'):
            file_path = file_path[1:]
        
        print(f"🚨 FILE ACCESS ATTEMPT: {file_path}")
        
        # Try to read the file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return jsonify({
            'protocol': 'file',
            'file_path': file_path,
            'content': content,
            'vulnerability': 'CRITICAL - Local file read via SSRF'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'File access failed: {str(e)}',
            'url': url,
            'vulnerability': 'File protocol SSRF attempted'
        }), 500

def handle_phar_protocol(url):
    """Handle phar:// protocol - PHP archive attacks"""
    try:
        # 🚨 VULNERABILITY: PHAR protocol can lead to deserialization attacks
        parsed = urlparse(url)
        
        return jsonify({
            'protocol': 'phar',
            'url': url,
            'warning': 'PHAR protocol accessed - potential deserialization vulnerability',
            'vulnerability': 'HIGH - PHAR deserialization via SSRF',
            'note': 'In PHP environments, this could lead to remote code execution'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'PHAR access failed: {str(e)}',
            'url': url,
            'vulnerability': 'PHAR protocol SSRF attempted'
        }), 500

def handle_gopher_protocol(url):
    """Handle gopher:// protocol - Internal service exploitation"""
    try:
        # 🚨 VULNERABILITY: Gopher protocol can exploit internal services
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 70
        path = parsed.path
        
        return jsonify({
            'protocol': 'gopher',
            'host': host,
            'port': port,
            'path': path,
            'warning': 'Gopher protocol accessed - internal service exploitation possible',
            'vulnerability': 'CRITICAL - Internal service access via Gopher',
            'common_attacks': [
                'Redis command injection',
                'SMTP command injection',
                'Internal service enumeration'
            ]
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Gopher access failed: {str(e)}',
            'url': url,
            'vulnerability': 'Gopher protocol SSRF attempted'
        }), 500

def handle_data_protocol(url):
    """Handle data:// protocol - Data URI scheme attacks"""
    try:
        # 🚨 VULNERABILITY: Data protocol can be used for XSS and code injection
        return jsonify({
            'protocol': 'data',
            'url': url,
            'warning': 'Data URI scheme accessed - potential XSS/code injection',
            'vulnerability': 'MEDIUM - Data URI injection via SSRF',
            'risks': [
                'Cross-site scripting (XSS)',
                'HTML injection',
                'JavaScript code execution'
            ]
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Data URI access failed: {str(e)}',
            'url': url,
            'vulnerability': 'Data protocol SSRF attempted'
        }), 500

def handle_dict_protocol(url):
    """Handle dict:// protocol - Service enumeration"""
    try:
        # 🚨 VULNERABILITY: Dict protocol can enumerate internal services
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 2628
        path = parsed.path
        
        return jsonify({
            'protocol': 'dict',
            'host': host,
            'port': port,
            'path': path,
            'warning': 'Dict protocol accessed - internal service enumeration possible',
            'vulnerability': 'MEDIUM - Service enumeration via Dict protocol',
            'common_targets': [
                'Redis (port 6379)',
                'Memcached (port 11211)',
                'Database services'
            ]
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Dict access failed: {str(e)}',
            'url': url,
            'vulnerability': 'Dict protocol SSRF attempted'
        }), 500

@app.route('/protected-proxy')
def protected_proxy():
    """
    ✅ PROTECTED: Only allows HTTP/HTTPS with validation
    This demonstrates the secure version
    """
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    # ✅ SECURITY: Validate URL scheme
    if not url.startswith(('http://', 'https://')):
        return jsonify({
            'error': 'Only HTTP and HTTPS protocols are allowed',
            'received_url': url,
            'allowed_protocols': ['http://', 'https://']
        }), 403
    
    try:
        response = requests.get(url, timeout=10, verify=True)
        return jsonify({
            'status': 'success',
            'protocol': 'http/https',
            'status_code': response.status_code,
            'content': response.text[:1000] + '...' if len(response.text) > 1000 else response.text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/create-test-file')
def create_test_file():
    """Create a test file for file:// protocol testing"""
    try:
        with open('test_file.txt', 'w') as f:
            f.write('This is a test file for SSRF demonstration.\n')
            f.write('Sensitive data: API_KEY=12345-SECRET-67890\n')
            f.write('Database URL: postgresql://user:pass@localhost:5432/db\n')
        
        return jsonify({
            'message': 'Test file created: test_file.txt',
            'test_url': 'file://test_file.txt',
            'content': 'This is a test file for SSRF demonstration.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚨 Starting VULNERABLE SSRF Application...")
    print("🔓 Vulnerable endpoints:")
    print("   - /get?url=file:///etc/passwd")
    print("   - /get?url=gopher://127.0.0.1:6379")
    print("   - /get?url=phar:///test.phar")
    print("   - /get?url=data:text/html,<script>")
    print("   - /get?url=dict://127.0.0.1:11211")
    print()
    print("✅ Protected endpoint:")
    print("   - /protected-proxy?url=https://httpbin.org/json")
    print()
    print("📊 Server info:")
    print("   - /create-test-file")
    print()
    print("🌐 Access the web interface at: http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)