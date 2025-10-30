from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import re

app = Flask(__name__)

"""ALLOWED_DOMAINS = {
    'api.example.com',
    'cdn.example.com',
    'public-api.com'
}"""

#BLOCKED_PORTS = {22, 25, 135, 443, 445, 1433, 1521, 3306, 3389, 5432}
ALLOWED_PORTS = {80, 443}


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

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in ['http', 'https']:
            return False
        
        #if parsed.hostname not in ALLOWED_DOMAINS:
        #    return False
        
        #if parsed.port and parsed.port in BLOCKED_PORTS:
        if parsed.port and parsed.port not in ALLOWED_PORTS:
            return False
        
        if parsed.hostname:
            if is_private_ip(parsed.hostname):
                return False
        
        return True
    except:
        return False

def is_private_ip(ip):
    private_patterns = [
        r'^localhost',          # localhost
        r'^127\.',          # localhost
        r'^10\.',           # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # 172.16.0.0/12
        r'^192\.168\.',     # 192.168.0.0/16
        r'^169\.254\.',     # Link-local
        r'^::1$',           # IPv6 localhost
        r'^fc00::',         # IPv6
        r'^fe80::'          # IPv6 link-local
    ]
    
    for pattern in private_patterns:
        if re.match(pattern, ip):
            return True
    
    return False

@app.route('/get')
def secure_proxy():
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid or forbidden URL'}), 403
    
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except requests.RequestException as e:
        return jsonify({'error': 'Request failed'}), 500

if __name__ == '__main__':
    app.run(debug=True)