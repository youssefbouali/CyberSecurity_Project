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