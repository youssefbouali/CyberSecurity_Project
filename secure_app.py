from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import re

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)