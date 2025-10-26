from flask import Flask, request, render_template_string
import requests
import json
import os

app = Flask(__name__)

# HTML Template for Critical Information Page

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