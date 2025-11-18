from flask import Flask, render_template, jsonify, session, request, redirect, url_for, flash, send_from_directory
import psutil
import platform
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from utils.reports import generate_report
from utils.auth import login_required
import smtplib
from email.message import EmailMessage
from threading import Thread
import os
from flask import render_template_string

app = Flask(__name__)
app.secret_key = 'supersecretkey123_change_in_production_2025'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['EMAIL_ENABLED'] = True
app.config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', 587))
app.config['EMAIL_USER'] = os.getenv('EMAIL_USER', 'your_email@gmail.com')
app.config['EMAIL_PASS'] = os.getenv('EMAIL_PASS', 'your_app_password')
app.config['ALERT_RECIPIENT'] = os.getenv('ALERT_RECIPIENT', 'admin@yourcompany.com')


USERS = {
    "radwa": generate_password_hash("1234"),
    "admin": generate_password_hash("password")
}

SENT_ALERTS = set()
SUSPICIOUS_PORTS = {21, 23, 445, 3389, 3306, 1433, 6379, 22, 3389, 5900}
SUSPICIOUS_PROCS = {'nc', 'netcat', 'ncat', 'socat', 'meterpreter', 'powershell.exe', 'mimikatz', 'cobaltstrike', 'empire'}

def get_open_ports():
    results = []
    try:
        connections = psutil.net_connections(kind='inet')
        seen = set()
        for conn  in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            ip, port = conn.laddr.ip, conn.laddr.port
            pid = conn.pid
            key = (ip, port, pid)
            if key in seen:
                continue
            seen.add(key)

            proc_name = "Unknown"
            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    proc_name = "Access Denied / Zombie"

            suspicious = False
            reasons = []
            if port in SUSPICIOUS_PORTS:
                suspicious = True
                reasons.append("Known vulnerable/exposed port")
            if proc_name.lower() and any(sp in proc_name.lower() for sp in SUSPICIOUS_PROCS):
                suspicious = True
                reasons.append("Suspicious process name")

            results.append({
                "ip": ip if ip else "0.0.0.0",
                "port": port,
                "pid": pid or "N/A",
                "process": proc_name,
                "suspicious": suspicious,
                "reason": ", ".join(reasons) if reasons else ""
            })
    except Exception as e:
        results.append({"error": f"Port scan error: {str(e)}"})
    return results

def get_system_info():
    try:
        uname = platform.uname()
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time

        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()

        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                info['cpu_percent'] = info['cpu_percent'] or 0.0
                info['memory_percent'] = info['memory_percent'] or 0.0
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        processes = processes[:20]

        return {
            "system": f"{uname.system} {uname.release}",
            "node": uname.node,
            "uptime": str(uptime).split('.')[0],
            "cpu_usage": round(cpu_usage, 1),
            "memory_total": round(memory.total / (1024**3), 1),
            "memory_used": round(memory.used / (1024**3), 1),
            "memory_percent": round(memory.percent, 1),
            "disk_percent": round(disk.percent, 1),
            "bytes_sent": round(net_io.bytes_sent / (1024**2), 1),
            "bytes_recv": round(net_io.bytes_recv / (1024**2), 1),
            "open_ports": get_open_ports(),
            "processes": processes
        }
    except Exception as e:
        return {"error": str(e)}

def send_email_alert(threat_data, system_info):
    if not app.config['EMAIL_ENABLED']:
        return

    subject = f"SECURITY ALERT - Suspicious Activity on {system_info['node']}"

    html_template = """
    <html>
    <body style="font-family: Arial, sans-serif; background:#0d1117; color:#f0f6fc; padding:20px;">
        <div style="max-width:700px; margin:auto; background:#161b22; padding:30px; border-radius:12px; border:1px solid #30363d;">
            <h1 style="color:#f85149; text-align:center;">SECURITY ALERT</h1>
            <p><strong>Host:</strong> {{ node }}</p>
            <p><strong>Time:</strong> {{ time }}</p>
            <p><strong>Threat Detected:</strong></p>
            <ul>
                {% for threat in threats %}
                <li><strong>{{ threat.port }}</strong> → {{ threat.process }} (PID: {{ threat.pid }})<br>
                    <small style="color:#f85149;">Reason: {{ threat.reason }}</small>
                </li>
                {% endfor %}
            </ul>
            <hr>
            <h3>System Snapshot</h3>
            <p>CPU: {{ cpu }}% | RAM: {{ ram }}% | Disk: {{ disk }}%</p>
            <p>Uptime: {{ uptime }}</p>
            <br>
            <small>SecureMonitor v1.0 – Automated Alert</small>
        </div>
    </body>
    </html>
    """

    html = render_template_string(html_template,
        node=system_info['node'],
        time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        threats=threat_data,
        cpu=system_info['cpu_usage'],
        ram=system_info['memory_percent'],
        disk=system_info['disk_percent'],
        uptime=system_info['uptime']
    )

    msg = EmailMessage()
    msg['From'] = app.config['EMAIL_USER']
    msg['To'] = app.config['ALERT_RECIPIENT']
    msg['Subject'] = subject
    msg.set_content("Your email client does not support HTML.")
    msg.add_alternative(html, subtype='html')

    try:
        with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
            server.starttls()
            server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASS'])
            server.send_message(msg)
        print(f"Email alert sent successfully!")
    except Exception as e:
        print(f"Email failed: {e}")

def async_email_alert(*args):
    Thread(target=send_email_alert, args=args).start()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/data')
@login_required
def data():
    return jsonify(get_system_info())

@app.route('/alerts')
@login_required
def alerts():
    info = get_system_info()
    port_alerts = [p for p in info.get('open_ports', []) if p.get('suspicious')]

    global SENT_ALERTS
    current_threats = {(p['port'], p['pid'] or 0) for p in port_alerts}
    previous_threats = SENT_ALERTS.copy()
 
    new_threats = current_threats - previous_threats
    if new_threats and app.config['EMAIL_ENABLED']:
        threat_details = [p for p in port_alerts if (p['port'], p['pid'] or 0) in new_threats]
        async_email_alert(threat_details, info)
  
    SENT_ALERTS = current_threats

    return jsonify({"alerts": port_alerts, "count": len(port_alerts)})

@app.route('/generate_report')
@login_required
def report():
    info = get_system_info()
    filename = generate_report(info) 
    return jsonify({
        "message": "Report generated successfully!",
        "download": f"/{filename}"
    })

@app.route('/static/reports/<path:filename>')
@login_required
def serve_report(filename):
    reports_dir = os.path.join(app.static_folder, 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and check_password_hash(USERS[username], password):
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Create reports folder if not exists
    os.makedirs("static/reports", exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=False)