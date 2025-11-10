from flask import Flask, render_template, jsonify
import psutil
import platform
import datetime
import os

app = Flask(__name__)

# List of suspicious ports & processes
SUSPICIOUS_PORTS = {21, 23, 445, 3389, 3306, 1433, 6379}
SUSPICIOUS_PROCS = {'nc', 'netcat', 'ncat', 'socat', 'meterpreter', 'powershell'}

def get_open_ports():
    results = []
    try:
        conns = psutil.net_connections(kind='inet')
        seen = set()
        for c in conns:
            if c.status != psutil.CONN_LISTEN:
                continue
            laddr = c.laddr
            port = laddr.port if hasattr(laddr, 'port') else (laddr[1] if len(laddr) > 1 else None)
            ip = laddr.ip if hasattr(laddr, 'ip') else (laddr[0] if len(laddr) > 0 else '')
            pid = c.pid or None
            key = (ip, port, pid)
            if key in seen:
                continue
            seen.add(key)
            proc_name = None
            try:
                if pid:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
            except:
                proc_name = None
            suspicious = False
            reason = []
            if port in SUSPICIOUS_PORTS:
                suspicious = True
                reason.append('suspicious_port')
            if proc_name:
                low = proc_name.lower()
                for sp in SUSPICIOUS_PROCS:
                    if sp in low:
                        suspicious = True
                        reason.append('suspicious_process')
                        break
            results.append({
                "ip": ip,
                "port": port,
                "pid": pid,
                "process": proc_name or "N/A",
                "suspicious": suspicious,
                "reason": reason
            })
    except Exception as e:
        results.append({"error": f"error_collecting_ports: {str(e)}"})
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
        return {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "uptime": str(uptime).split('.')[0],
            "cpu_usage": cpu_usage,
            "memory_percent": memory.percent,
            "disk_percent": disk.percent,
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "open_ports": get_open_ports()
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    return jsonify(get_system_info())

if __name__ == '__main__':
    app.run(debug=True)
