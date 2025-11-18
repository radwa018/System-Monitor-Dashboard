SUSPICIOUS_PORTS = {21, 23, 445, 3389, 3306, 1433, 6379}
SUSPICIOUS_PROCS = {'nc', 'netcat', 'ncat', 'socat', 'meterpreter', 'powershell'}

def check_suspicious(open_ports):
    alerts = []
    for port in open_ports:
        if port['suspicious']:
            alerts.append(f"{port['process']} on port {port['port']} is suspicious ({', '.join(port['reason'])})")
    return alerts
