from flask import Flask, request, render_template_string
import requests
import json
import os

app = Flask(__name__)

# HTML Template for Critical Information Page
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 Internal Admin Dashboard - CRITICAL</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .critical-banner {
            background: #ff4444;
            color: white;
            padding: 15px;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
            border-radius: 10px;
            margin-bottom: 20px;
            animation: blink 2s infinite;
        }
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .dashboard {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid #ff4444;
            padding-bottom: 20px;
        }
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: #666;
            font-size: 1.2em;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            border-left: 5px solid #ff4444;
        }
        .card.critical {
            border-left-color: #ff4444;
            background: #fff5f5;
        }
        .card.warning {
            border-left-color: #ffaa00;
            background: #fffbf0;
        }
        .card.info {
            border-left-color: #007bff;
            background: #f0f8ff;
        }
        .card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        .info-item {
            margin-bottom: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 3px solid #007bff;
        }
        .info-item.critical {
            background: #ffe6e6;
            border-left-color: #ff4444;
            font-weight: bold;
        }
        .info-item.warning {
            background: #fff3cd;
            border-left-color: #ffaa00;
        }
        .secret-data {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }
        .system-status {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        .status-item {
            text-align: center;
            padding: 15px;
        }
        .status-item .indicator {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin: 0 auto 10px;
        }
        .status-online { background: #28a745; }
        .status-offline { background: #dc3545; }
        .status-warning { background: #ffc107; }
        .api-section {
            background: #34495e;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .api-endpoint {
            background: #2c3e50;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        .download-section {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            background: #e9ecef;
            border-radius: 10px;
        }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 5px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #0056b3;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="critical-banner">
            ⚠️ CRITICAL INTERNAL SYSTEM - RESTRICTED ACCESS ⚠️
        </div>
        
        <div class="dashboard">
            <div class="header">
                <h1>🔐 Internal Admin Dashboard</h1>
                <div class="subtitle">Sensitive System Information - FOR INTERNAL USE ONLY</div>
            </div>

            <div class="system-status">
                <div class="status-item">
                    <div class="indicator status-online"></div>
                    <div>Database</div>
                    <strong>ONLINE</strong>
                </div>
                <div class="status-item">
                    <div class="indicator status-online"></div>
                    <div>API Server</div>
                    <strong>ONLINE</strong>
                </div>
                <div class="status-item">
                    <div class="indicator status-warning"></div>
                    <div>Firewall</div>
                    <strong>WARNING</strong>
                </div>
            </div>

            <div class="grid">
                <!-- System Information Card -->
                <div class="card critical">
                    <h3>🚨 System Credentials</h3>
                    <div class="info-item critical">
                        <strong>Admin Username:</strong> root_admin
                    </div>
                    <div class="info-item critical">
                        <strong>Default Password:</strong> P@ssw0rd123!
                    </div>
                    <div class="info-item critical">
                        <strong>SSH Key:</strong> ssh-rsa AAAAB3NzaC1yc2E... admin@internal
                    </div>
                    <div class="info-item warning">
                        <strong>Last Login:</strong> 2024-01-15 14:30:22 from 192.168.1.100
                    </div>
                </div>

                <!-- Database Information Card -->
                <div class="card critical">
                    <h3>🗄️ Database Access</h3>
                    <div class="info-item critical">
                        <strong>DB Host:</strong> 127.0.0.1:5432
                    </div>
                    <div class="info-item critical">
                        <strong>DB Name:</strong> company_secrets
                    </div>
                    <div class="info-item critical">
                        <strong>DB User:</strong> postgres_admin
                    </div>
                    <div class="info-item critical">
                        <strong>DB Password:</strong> db_secret_2024!
                    </div>
                </div>

                <!-- Network Configuration Card -->
                <div class="card warning">
                    <h3>🌐 Network Configuration</h3>
                    <div class="info-item">
                        <strong>Internal IP:</strong> 192.168.1.1
                    </div>
                    <div class="info-item">
                        <strong>Subnet Mask:</strong> 255.255.255.0
                    </div>
                    <div class="info-item">
                        <strong>Gateway:</strong> 192.168.1.254
                    </div>
                    <div class="info-item warning">
                        <strong>VPN Config:</strong> vpn_internal.ovpn
                    </div>
                </div>

                <!-- API Keys Card -->
                <div class="card critical">
                    <h3>🔑 API Access Keys</h3>
                    <div class="info-item critical">
                        <strong>AWS Access Key:</strong> AKIAIOSFODNN7EXAMPLE
                    </div>
                    <div class="info-item critical">
                        <strong>AWS Secret Key:</strong> wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                    </div>
                    <div class="info-item critical">
                        <strong>Stripe API Key:</strong> sk_test_4eC39HqLyjWDarjtT1zdp7dc
                    </div>
                    <div class="info-item critical">
                        <strong>JWT Secret:</strong> super_secret_jwt_key_2024!
                    </div>
                </div>
            </div>

            <!-- Secret Data Section -->
            <div class="card critical">
                <h3>📁 Confidential Data Files</h3>
                <div class="secret-data">
                    /etc/passwd contents:<br>
                    root:x:0:0:root:/root:/bin/bash<br>
                    admin:x:1000:1000:Admin User:/home/admin:/bin/bash<br>
                    postgres:x:101:101:PostgreSQL:/var/lib/postgresql:/bin/bash
                </div>
                <div class="secret-data">
                    /etc/shadow excerpt:<br>
                    root:$6$rounds=656000$H1lDprmB$...:19455:0:99999:7:::<br>
                    admin:$6$rounds=656000$abc123def$...:19455:0:99999:7:::
                </div>
            </div>

            <!-- Environment Variables -->
            <div class="card critical">
                <h3>⚙️ Environment Configuration</h3>
                <div class="secret-data">
                    DATABASE_URL=postgresql://admin:secret@192.168.1.1:5432/production<br>
                    REDIS_URL=redis://192.168.1.1:6379/0<br>
                    SECRET_KEY=this_is_very_secret_key_2024!<br>
                    AWS_BUCKET=company-private-files<br>
                    SMTP_PASSWORD=email_password_123!
                </div>
            </div>

            <!-- API Endpoints -->
            <div class="api-section">
                <h3>🔌 Internal API Endpoints</h3>
                <div class="api-endpoint">
                    GET /api/v1/users/credentials - Get all user credentials
                </div>
                <div class="api-endpoint">
                    POST /api/v1/admin/execute - Execute system commands
                </div>
                <div class="api-endpoint">
                    GET /api/v1/database/backup - Download database backup
                </div>
                <div class="api-endpoint">
                    POST /api/v1/firewall/disable - Disable firewall rules
                </div>
            </div>

            <!-- Download Section -->
            <div class="download-section">
                <h3>💾 Download Critical Information</h3>
                <p>This information should be protected and never exposed publicly!</p>
                <a href="/download/critical" class="btn btn-danger">📥 Download Full Report</a>
                <a href="/download/config" class="btn">⚙️ Download Config Files</a>
                <a href="/download/backup" class="btn">🗄️ Download Database Backup</a>
            </div>

            <div class="footer">
                <p>⚠️ <strong>SECURITY WARNING:</strong> This page contains sensitive internal information.</p>
                <p>Access should be restricted to authorized personnel only.</p>
                <p>Last updated: 2024-01-15 14:35:00 UTC</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

# Additional critical data for download
CRITICAL_DATA = {
    "system_credentials": {
        "ssh_keys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... admin@server1",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... root@server2"
        ],
        "database_passwords": {
            "mysql_root": "MySQL_R00t_P@ss!",
            "postgres_admin": "PgAdmin_Secret_2024",
            "mongodb": "MongoDB_Default_123"
        },
        "api_tokens": {
            "slack": "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
            "github": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            "docker": "dckr_pat_abcdefghijklmnopqrstuvw"
        }
    },
    "network_config": {
        "vpn_config": "client\ndev tun\nremote vpn.company.com 1194\nsecret static.key",
        "internal_services": [
            "http://192.168.1.10:8080/admin",
            "http://192.168.1.20:3000/dashboard", 
            "http://192.168.1.30:5432/phppgadmin"
        ]
    },
    "sensitive_files": {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash",
        "/etc/shadow": "root:$6$...:19455:0:99999:7:::\nadmin:$6$...:19455:0:99999:7:::",
        "/.env": "SECRET_KEY=super_secret_key_2024\nDATABASE_PASSWORD=db_pass_123"
    }
}

@app.route('/')
def critical_dashboard():
    """Main critical information dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/admin')
def admin_panel():
    """Admin panel with additional sensitive data"""
    admin_html = HTML_TEMPLATE.replace('Internal Admin Dashboard', 'ADMIN PANEL - SUPER USER ACCESS')
    admin_html = admin_html.replace('card critical', 'card critical super-admin')
    return render_template_string(admin_html)

@app.route('/api/data')
def api_data():
    """API endpoint returning critical data"""
    return json.dumps(CRITICAL_DATA, indent=2)

@app.route('/download/critical')
def download_critical():
    """Download comprehensive critical data"""
    critical_report = f"""
CRITICAL SYSTEM INFORMATION REPORT
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
============================================================

SYSTEM CREDENTIALS:
-------------------
{json.dumps(CRITICAL_DATA['system_credentials'], indent=2)}

NETWORK CONFIGURATION:
----------------------
{json.dumps(CRITICAL_DATA['network_config'], indent=2)}

SENSITIVE FILES:
----------------
{json.dumps(CRITICAL_DATA['sensitive_files'], indent=2)}

SECURITY WARNING:
-----------------
This file contains extremely sensitive information that could
compromise the entire system if exposed to unauthorized parties.

- Change all passwords immediately if this file is leaked
- Rotate all API keys and tokens
- Review system access logs for suspicious activity
- Notify security team immediately
    """
    
    from flask import Response
    return Response(
        critical_report,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=critical_system_report.txt"}
    )

@app.route('/download/config')
def download_config():
    """Download configuration files"""
    config_data = """
# CRITICAL CONFIGURATION FILES
# ============================

# Database Configuration
DATABASE_HOST=127.0.0.1
DATABASE_PORT=5432
DATABASE_NAME=company_production
DATABASE_USER=postgres_admin
DATABASE_PASSWORD=SuperSecretDB2024!

# Application Secrets
SECRET_KEY_BASE=this_is_very_secret_dont_share_2024
JWT_SECRET=json_web_token_secret_key_123
ENCRYPTION_KEY=32_byte_encryption_key_here_2024!

# External Services
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc

# Security Settings
ADMIN_USERNAME=super_admin
ADMIN_PASSWORD=AdminP@ssw0rd2024!
SSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
[REDACTED FOR SECURITY]
-----END RSA PRIVATE KEY-----
    """
    
    from flask import Response
    return Response(
        config_data,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=system_configuration.txt"}
    )

@app.route('/download/backup')
def download_backup():
    """Simulate database backup download"""
    backup_data = """
-- DATABASE BACKUP DUMP
-- Company Internal Systems
-- WARNING: Contains sensitive user data

-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sample Data (REDACTED)
INSERT INTO users (username, password_hash, email, is_admin) VALUES
('admin', '$2b$12$LQv3c1yqBWVHxkd0L8k4VeMc', 'admin@company.com', TRUE),
('john.doe', '$2b$12$abc123def456ghi789jkl', 'john@company.com', FALSE);

-- API Keys Table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- System Configuration
CREATE TABLE system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    is_sensitive BOOLEAN DEFAULT FALSE
);

-- WARNING: This backup contains live production data
-- Handle with extreme security precautions
    """
    
    from flask import Response
    return Response(
        backup_data,
        mimetype="text/sql",
        headers={"Content-Disposition": "attachment;filename=database_backup.sql"}
    )

@app.route('/ssrf-test')
def ssrf_test_endpoint():
    """Vulnerable endpoint for SSRF testing"""
    url = request.args.get('url')
    if url:
        try:
            response = requests.get(url, timeout=5, verify=False)
            # This is intentionally vulnerable - it reflects external content
            return f"""
            <html>
            <body>
                <h2>SSRF Test Result</h2>
                <p>URL: {url}</p>
                <p>Status Code: {response.status_code}</p>
                <div style="border: 1px solid #ccc; padding: 10px; margin: 10px;">
                    <h3>Response Content (first 1000 chars):</h3>
                    <pre>{response.text[:1000]}</pre>
                </div>
                <br>
                <a href="/">← Back to Dashboard</a>
            </body>
            </html>
            """
        except Exception as e:
            return f"""
            <html>
            <body>
                <h2>SSRF Test Error</h2>
                <p>URL: {url}</p>
                <p>Error: {str(e)}</p>
                <a href="/">← Back to Dashboard</a>
            </body>
            </html>
            """
    
    return '''
    <html>
    <body>
        <h2>SSRF Testing Endpoint</h2>
        <form method="get">
            <input type="text" name="url" placeholder="Enter URL to fetch" size="50">
            <input type="submit" value="Test SSRF">
        </form>
        <p>Example: /ssrf-test?url=http://192.168.1.1/admin</p>
        <a href="/">← Back to Dashboard</a>
    </body>
    </html>
    '''

import time

if __name__ == '__main__':
    # Print startup information
    print("🚨 CRITICAL SYSTEM SIMULATION STARTED")
    print("=" * 50)
    print("🌐 Internal Admin Dashboard: http://192.168.1.1:80/")
    print("🔐 Admin Panel: http://192.168.1.1:80/admin") 
    print("📊 API Data: http://192.168.1.1:80/api/data")
    print("🕵️ SSRF Test: http://192.168.1.1:80/ssrf-test")
    print("💾 Download Endpoints:")
    print("   - Critical Report: http://192.168.1.1:80/download/critical")
    print("   - Config Files: http://192.168.1.1:80/download/config")
    print("   - Database Backup: http://192.168.1.1:80/download/backup")
    print("")
    print("⚠️  WARNING: This server contains simulated sensitive data")
    print("    for SSRF vulnerability testing purposes only!")
    print("=" * 50)
    
    # Run the application
    app.run(host='192.168.1.1', port=80, debug=False)