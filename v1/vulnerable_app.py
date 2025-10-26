from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/get')
def vulnerable_proxy():
    url = request.args.get('url')
    
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)