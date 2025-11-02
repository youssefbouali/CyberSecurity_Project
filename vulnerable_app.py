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
    <title>URL Fetcher</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            width: 100%;
            max-width: 600px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        .form-group {
            margin-bottom: 25px;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        button {
            width: 100%;
            padding: 15px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        button:hover {
            background: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .examples {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-top: 25px;
        }
        .examples h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        .example-links {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .example-link {
            color: #3498db;
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 6px;
            transition: all 0.2s ease;
            font-size: 14px;
        }
        .example-link:hover {
            background: #e3f2fd;
            color: #2980b9;
        }
        .results {
            margin-top: 25px;
            display: none;
        }
        .results h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 14px;
            line-height: 1.4;
            max-height: 400px;
            overflow-y: auto;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .loading-spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
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

@app.route('/get')
def vulnerable_proxy():
    """
    🚨 VULNERABLE: No validation - accepts any protocol
    This demonstrates critical SSRF vulnerability
    """
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    print(f"🚨 ACCESSED: {url}")
    
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
            #'vulnerability': 'CRITICAL - Local file read via SSRF'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'File access failed: {str(e)}',
            'url': url,
            #'vulnerability': 'File protocol SSRF attempted'
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
            #'vulnerability': 'HIGH - PHAR deserialization via SSRF',
            'note': 'In PHP environments, this could lead to remote code execution'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'PHAR access failed: {str(e)}',
            'url': url,
            #'vulnerability': 'PHAR protocol SSRF attempted'
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
            #'vulnerability': 'CRITICAL - Internal service access via Gopher',
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
            #'vulnerability': 'Gopher protocol SSRF attempted'
        }), 500

def handle_data_protocol(url):
    """Handle data:// protocol - Data URI scheme attacks"""
    try:
        # 🚨 VULNERABILITY: Data protocol can be used for XSS and code injection
        return jsonify({
            'protocol': 'data',
            'url': url,
            'warning': 'Data URI scheme accessed - potential XSS/code injection',
            #'vulnerability': 'MEDIUM - Data URI injection via SSRF',
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
            #'vulnerability': 'Data protocol SSRF attempted'
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
            #'vulnerability': 'Dict protocol SSRF attempted'
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