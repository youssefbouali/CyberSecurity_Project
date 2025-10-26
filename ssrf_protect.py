import ssrf_protect
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/get')
@ssrf_protect.protect_ssrf
def protected_proxy():
    url = request.args.get('url')
    
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except requests.RequestException as e:
        return jsonify({'error': 'Request failed'}), 500