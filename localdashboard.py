from flask import Flask, request, render_template
import requests

app = Flask(__name__)

@app.route('/')
def admin_dashboard():
    """Admin dashboard with full HTML interface"""
    # Check if URL parameter is provided for SSRF testing
    url = request.args.get('url')
    if url:
        # Vulnerable SSRF implementation - No validation
        try:
            response = requests.get(url, timeout=5)
            return render_template('dashboard.html', url=url, status_code=response.status_code, text=response.text[:500])

        except Exception as e:
            return render_template('dashboard.html', url=url, error=str(e))
    
    return render_template('dashboard.html')

@app.route('/api/data')
def api_data():
    """Mock API endpoint for testing"""
    return {
        "status": "success",
        "service": "Admin API",
        "port": 80,
        "endpoints": [
            "/admin",
            "/api/data", 
            "/api/users"
        ],
        "data": {
            "users_count": 1524,
            "server_status": "running",
            "version": "1.0.0"
        }
    }

@app.route('/api/users')
def api_users():
    """Mock users API endpoint"""
    return {
        "users": [
            {"id": 1, "name": "Admin User", "role": "administrator"},
            {"id": 2, "name": "Test User", "role": "user"}
        ]
    }

if __name__ == '__main__':
    # Print startup information
    print("🌐 Starting application on port 80...")
    print("📊 Admin Dashboard: http://localhost/admin")
    print("🏠 Home Page: http://localhost/")
    print("🔧 API: http://localhost/api/data")
    
    # Run the application on port 80
    # Note: Requires sudo privileges on Linux/Mac
    app.run(host='0.0.0.0', port=8080, debug=False)