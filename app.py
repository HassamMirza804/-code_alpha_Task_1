from flask import Flask, render_template, jsonify
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import time

app = Flask(__name__)

# Global variable to store packet info
packet_info = []

def packet_capture():
    global packet_info
    while True:
        packets = sniff(count=1)  # Capture 1 packet at a time
        for packet in packets:
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                
                # Append packet info to the global list
                packet_info.append({
                    'source': ip_src,
                    'destination': ip_dst,
                    'protocol': protocol
                })
                time.sleep(1)  # Minor delay between each capture

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/capture', methods=['POST'])
def capture():
    threading.Thread(target=packet_capture, daemon=True).start()  # Start capturing in a thread
    return 'Capturing packets...'

@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify(packet_info)  # Return captured packet info as JSON

if __name__ == "__main__":
    app.run(debug=True)