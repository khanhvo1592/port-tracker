from flask import Flask, render_template, request, jsonify
import socket
from scapy.all import *

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # Ensure you have an index.html with the appropriate form

@app.route('/check_port', methods=['POST'])
def check_port():
    data = request.json
    domain = data['domain']
    port = int(data['port'])
    protocol = data.get('protocol', 'tcp').lower()  # Default to TCP if not specified

    if protocol == 'tcp':
        return check_tcp_port(domain, port)
    elif protocol == 'udp':
        return check_udp_port(domain, port)
    else:
        return jsonify({'error': 'Unsupported protocol'}), 400

def check_tcp_port(domain, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Timeout for the socket to wait for a connection
    result = sock.connect_ex((domain, port))

    if result == 0:
        status = "Open"
    else:
        status = "Closed or not reachable"
    
    sock.close()
    return jsonify({'domain': domain, 'port': port, 'protocol': 'TCP', 'status': status})

def check_udp_port(domain, port):
    packet = IP(dst=domain)/UDP(dport=port)
    response = sr1(packet, timeout=2, verbose=0)
    if response is None:
        status = "Filtered or open"
    else:
        if response.haslayer(UDP):
            status = "Open"
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                status = "Closed"
            else:
                status = "Filtered or open"
        else:
            status = "Closed or not reachable"
    
    return jsonify({'domain': domain, 'port': port, 'protocol': 'UDP', 'status': status})

if __name__ == '__main__':
    app.run(debug=True)
