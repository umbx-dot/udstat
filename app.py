from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
import socket
import threading
import time
import os
import sys
from collections import deque
import struct
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_idom_key_l4_udp_only_v1!'
socketio = SocketIO(app, async_mode='gevent')

MONITORED_UDP_PORT = 53
WEB_APP_PORT = 5000

l4_stats_totals = {
    'udp_packets_count': 0,
    'udp_bytes_count': 0,
    'fragmented_packets_count': 0,
}

l4_stats_live = {
    'pps': 0,
    'bps': 0,
    'udp_percentage': 0,
    'fragmented_percentage': 0
}

l4_lock = threading.Lock()

MAX_HISTORY = 60 
l4_pps_history = deque([0] * MAX_HISTORY, maxlen=MAX_HISTORY)
l4_bps_history = deque([0] * MAX_HISTORY, maxlen=MAX_HISTORY)

def get_public_ip():
    try:
        response = requests.get('https://ipv4.icanhazip.com', timeout=5)
        return response.text.strip()
    except:
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text.strip()
        except:
            try:
                response = requests.get('https://checkip.amazonaws.com', timeout=5)
                return response.text.strip()
            except:
                return '0.0.0.0'

PUBLIC_IP = get_public_ip()

def l4_udp_packet_listener(target_port):
    global l4_stats_totals
    s = None
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0))
        
        print(f"LISTENER: UDP port {target_port} active on Ubuntu")

        while True:
            try:
                packet, addr = s.recvfrom(65535)
                
                if len(packet) < 20: 
                    continue

                ip_header_data = packet[:20]
                ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_data)
                
                ip_version_ihl = ip_header[0]
                ip_header_length = (ip_version_ihl & 0xF) * 4
                
                if ip_header_length > len(packet) or ip_header_length < 20:
                    continue

                actual_ip_protocol = ip_header[6]
                
                if actual_ip_protocol != socket.IPPROTO_UDP:
                    continue
                
                flags_fragment_offset_word = ip_header[4]
                is_fragmented = ((flags_fragment_offset_word >> 13) & 0x1) or ((flags_fragment_offset_word & 0x1FFF) != 0)
                
                if len(packet) < ip_header_length + 8:
                    continue
                udp_header_data = packet[ip_header_length:ip_header_length+8]
                udp_header = struct.unpack('!HHHH', udp_header_data)
                actual_dst_port = udp_header[1]

                if actual_dst_port == target_port:
                    with l4_lock:
                        l4_stats_totals['udp_packets_count'] += 1
                        l4_stats_totals['udp_bytes_count'] += len(packet)
                        if is_fragmented: 
                             l4_stats_totals['fragmented_packets_count'] +=1
            except socket.timeout:
                continue
            except socket.error as se:
                if se.errno == 4:
                    continue
                else:
                    time.sleep(0.001)
            except Exception:
                time.sleep(0.001)
                
    except OSError as e:
        print(f"FATAL OS-Error: Could not initialize listener for UDP port {target_port}: {e}.")
    except Exception as e:
        print(f"FATAL Error setting up listener for UDP port {target_port}: {e}")
    finally:
        if s:
            s.close()
            print(f"CLOSED: Listener for UDP port {target_port}")


def calculate_rates():
    global l4_stats_totals, l4_stats_live, l4_pps_history, l4_bps_history
    prev_total_udp_packets = 0
    prev_total_udp_bytes = 0
    prev_total_fragmented_packets = 0
    
    while True:
        time.sleep(1.0)
        with l4_lock:
            current_total_udp_packets = l4_stats_totals['udp_packets_count']
            current_total_udp_bytes = l4_stats_totals['udp_bytes_count']
            current_total_fragmented_packets = l4_stats_totals['fragmented_packets_count']

            interval_udp_packets = current_total_udp_packets - prev_total_udp_packets
            interval_udp_bytes = current_total_udp_bytes - prev_total_udp_bytes
            interval_fragmented_packets = current_total_fragmented_packets - prev_total_fragmented_packets

            l4_stats_live['pps'] = interval_udp_packets
            l4_stats_live['bps'] = interval_udp_bytes
            
            if interval_udp_packets > 0:
                l4_stats_live['udp_percentage'] = 100.0 
                l4_stats_live['fragmented_percentage'] = round((interval_fragmented_packets / interval_udp_packets) * 100, 1)
            else:
                l4_stats_live['udp_percentage'] = 0
                l4_stats_live['fragmented_percentage'] = 0

            l4_pps_history.append(l4_stats_live['pps'])
            l4_bps_history.append(l4_stats_live['bps'])

            prev_total_udp_packets = current_total_udp_packets
            prev_total_udp_bytes = current_total_udp_bytes
            prev_total_fragmented_packets = current_total_fragmented_packets

        socketio.emit('l4_update', {
            'pps': l4_stats_live['pps'], 
            'bps': l4_stats_live['bps'], 
            'history_pps': list(l4_pps_history), 
            'history_bps': list(l4_bps_history),
            'udp_percentage': l4_stats_live['udp_percentage'],
            'fragmented_percentage': l4_stats_live['fragmented_percentage']
        }, namespace='/l4')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/l4')
def l4_dstat_page():
    return render_template('l4_dstat.html', 
                           server_ip_info=PUBLIC_IP, 
                           udp_port=MONITORED_UDP_PORT)

@socketio.on('connect', namespace='/l4')
def l4_connect():
    with l4_lock:
        socketio.emit('l4_update', {
            'pps': l4_stats_live['pps'], 
            'bps': l4_stats_live['bps'], 
            'history_pps': list(l4_pps_history), 
            'history_bps': list(l4_bps_history),
            'udp_percentage': l4_stats_live['udp_percentage'],
            'fragmented_percentage': l4_stats_live['fragmented_percentage']
        }, namespace='/l4')


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("FATAL: Script must be run as root for raw socket access.")
        print("Please run with: sudo python3 app.py")
        sys.exit(1)
    
    print("Running as root on Ubuntu.")

    print(f"iDOM - Dstats (L4 UDP Focus) starting...")
    print(f"Server public IP detected as: {PUBLIC_IP}")
    print(f"Web interface will be available at http://{PUBLIC_IP}:{WEB_APP_PORT}")
    print(f"Monitoring UDP port {MONITORED_UDP_PORT} on all interfaces.")
    
    raw_udp_thread = threading.Thread(target=l4_udp_packet_listener, args=(MONITORED_UDP_PORT,), daemon=True)
    rates_thread = threading.Thread(target=calculate_rates, daemon=True)

    raw_udp_thread.start()
    rates_thread.start()

    try:
        socketio.run(app, host='0.0.0.0', port=WEB_APP_PORT, use_reloader=False, log_output=False)
    except OSError as e:
        err_code = e.errno
        if err_code == 98:
             print(f"FATAL: Port {WEB_APP_PORT} is already in use (Error: {err_code}). Please free the port or choose another.")
        else:
            print(f"FATAL: Could not start web server on port {WEB_APP_PORT} (Error: {err_code}): {e}")
    except Exception as e:
        print(f"FATAL: An unexpected error occurred while starting web server: {e}")
