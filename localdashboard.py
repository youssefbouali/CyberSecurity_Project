from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

# HTML Template for Admin Dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 1.2em;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.4em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            display: block;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 25px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            margin: 5px;
            transition: background 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1em;
        }
        
        .btn:hover {
            background: #764ba2;
        }
        
        .btn-danger {
            background: #e74c3c;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .btn-success {
            background: #27ae60;
        }
        
        .btn-success:hover {
            background: #219a52;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: bold;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus, .form-group select:focus {
            border-color: #667eea;
            outline: none;
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            background: #e74c3c;
            color: white;
        }
        
        .alert.success {
            background: #27ae60;
        }
        
        .alert.warning {
            background: #f39c12;
        }
        
        .logs {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            max-height: 300px;
            overflow-y: auto;
            margin-top: 20px;
        }
        
        .log-entry {
            padding: 5px 0;
            border-bottom: 1px solid #34495e;
        }
        
        .timestamp {
            color: #3498db;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .stats {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Admin Dashboard</h1>
            <p>Application running on Port 80 | System Management</p>
        </div>

        <div class="dashboard">
            <!-- System Statistics Card -->
            <div class="card">
                <h3>📊 System Statistics</h3>
                <div class="stats">
                    <div class="stat-item">
                        <span class="stat-number">1,524</span>
                        <span class="stat-label">Active Users</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">98.7%</span>
                        <span class="stat-label">Uptime</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">45</span>
                        <span class="stat-label">Requests/sec</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">2.3s</span>
                        <span class="stat-label">Avg Response</span>
                    </div>
                </div>
            </div>

            <!-- Quick Actions Card -->
            <div class="card">
                <h3>⚡ Quick Actions</h3>
                <div style="margin-top: 20px;">
                    <button class="btn btn-success" onclick="restartServices()">🔄 Restart Services</button>
                    <button class="btn" onclick="backupSystem()">💾 Backup System</button>
                    <button class="btn btn-danger" onclick="clearCache()">🗑️ Clear Cache</button>
                    <button class="btn" onclick="showLogs()">📋 System Logs</button>
                </div>
            </div>

            <!-- User Management Card -->
            <div class="card">
                <h3>👥 User Management</h3>
                <div class="form-group">
                    <label>Search User:</label>
                    <input type="text" id="userSearch" placeholder="Enter username...">
                </div>
                <button class="btn" onclick="searchUser()">🔍 Search</button>
                <button class="btn btn-success" onclick="addUser()">➕ Add User</button>
            </div>

            <!-- System Security Card -->
            <div class="card">
                <h3>🛡️ System Security</h3>
                <div class="alert warning">
                    ⚠️ System running on Port 80 - Verify firewall settings
                </div>
                <div class="form-group">
                    <label>Check URL:</label>
                    <input type="text" id="urlCheck" placeholder="https://example.com" value="http://localhost:80/admin">
                </div>
                <button class="btn" onclick="checkURL()">🔒 Security Check</button>
                <button class="btn btn-danger" onclick="blockIP()">🚫 Block IP</button>
            </div>
        </div>

        <!-- System Logs Section -->
        <div class="card">
            <h3>📋 Recent System Logs</h3>
            <div class="logs" id="systemLogs">
                <div class="log-entry"><span class="timestamp">[12:30:45]</span> System running on port 80</div>
                <div class="log-entry"><span class="timestamp">[12:28:12]</span> Ready to accept requests</div>
                <div class="log-entry"><span class="timestamp">[12:25:33]</span> Admin dashboard loaded</div>
                <div class="log-entry"><span class="timestamp">[12:20:01]</span> Database initialization complete</div>
                <div class="log-entry"><span class="timestamp">[12:15:47]</span> Server startup initiated</div>
            </div>
        </div>

    </div>

    <script>
        // Restart system services
        function restartServices() {
            addLog('Starting services restart...');
            setTimeout(() => {
                addLog('Services restarted successfully');
                showAlert('Services restarted successfully', 'success');
            }, 2000);
        }

        // Create system backup
        function backupSystem() {
            addLog('Starting system backup...');
            setTimeout(() => {
                addLog('Backup completed successfully');
                showAlert('Backup created successfully', 'success');
            }, 3000);
        }

        // Clear system cache
        function clearCache() {
            addLog('Clearing cache memory...');
            setTimeout(() => {
                addLog('Cache cleared successfully');
                showAlert('Cache cleared successfully', 'success');
            }, 1500);
        }

        // Display system logs
        function showLogs() {
            addLog('Displaying full system logs...');
            showAlert('Loading complete logs...', 'warning');
        }

        // Search for user
        function searchUser() {
            const username = document.getElementById('userSearch').value;
            if (username) {
                addLog(`Searching for user: ${username}`);
                showAlert(`Searching for user: ${username}`, 'warning');
            }
        }

        // Add new user
        function addUser() {
            addLog('Opening new user form...');
            showAlert('Loading user addition form', 'warning');
        }

        // Check URL security
        function checkURL() {
            const url = document.getElementById('urlCheck').value;
            addLog(`Security checking URL: ${url}`);
            showAlert(`Scanning URL security: ${url}`, 'warning');
        }

        // Block IP address
        function blockIP() {
            addLog('Opening IP blocking window...');
            showAlert('Loading IP blocking tool', 'warning');
        }

        // Add log entry to system logs
        function addLog(message) {
            const logsContainer = document.getElementById('systemLogs');
            const timestamp = new Date().toLocaleTimeString();
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${message}`;
            logsContainer.prepend(logEntry);
        }

        // Show alert message
        function showAlert(message, type = '') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert ${type}`;
            alertDiv.textContent = message;
            
            const header = document.querySelector('.header');
            header.after(alertDiv);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }

        // Add some automatic logs
        setTimeout(() => {
            addLog('User interface initialization completed');
        }, 1000);

        setTimeout(() => {
            addLog('All modules ready for operation');
        }, 2000);
    </script>
</body>
</html>
"""

@app.route('/')
def admin_dashboard():
    """Admin dashboard with full HTML interface"""
    # Check if URL parameter is provided for SSRF testing
    url = request.args.get('url')
    if url:
        # Vulnerable SSRF implementation - No validation
        try:
            response = requests.get(url, timeout=5)
            # Return both the dashboard and the SSRF response
            return render_template_string(HTML_TEMPLATE + f"""
            <div class="alert warning">
                <h4>SSRF Test Result:</h4>
                <p><strong>URL:</strong> {url}</p>
                <p><strong>Status Code:</strong> {response.status_code}</p>
                <pre>{response.text[:500]}</pre>
            </div>
            """)
        except Exception as e:
            return render_template_string(HTML_TEMPLATE + f"""
            <div class="alert">
                <h4>SSRF Test Failed:</h4>
                <p><strong>URL:</strong> {url}</p>
                <p><strong>Error:</strong> {str(e)}</p>
            </div>
            """)
    
    return render_template_string(HTML_TEMPLATE)

@app.route('/')
def home():
    """Home page with navigation"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Main Application - Port 80</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #333; }
            .nav { margin: 20px 0; }
            .btn { display: inline-block; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Web Application Running on Port 80</h1>
            <p>This application is running on port 80 and contains an admin dashboard.</p>
            
            <div class="nav">
                <a href="/admin" class="btn">🚀 Go to Admin Dashboard</a>
                <a href="/admin?url=http://example.com" class="btn">🔍 Test SSRF</a>
            </div>
            
            <h3>Available Endpoints:</h3>
            <ul>
                <li><code>/admin</code> - Admin Dashboard</li>
                <li><code>/admin?url=...</code> - Proxy Test (SSRF)</li>
                <li><code>/api/data</code> - API Endpoint</li>
            </ul>
        </div>
    </body>
    </html>
    """

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
    app.run(host='0.0.0.0', port=80, debug=False)