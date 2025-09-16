import pandas as pd
import requests
import time
import os
from flask import Flask, request, render_template, redirect, Response
import threading
import pyshark
import asyncio
from collections import deque

# Output file for results
OUTPUT_FILE = "vt_results.csv"
API_KEY = None  # global variable for VirusTotal API key


def check_ip_virustotal(ip,vt_api_key):
    
    """Query VirusTotal for an IP address reputation"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": vt_api_key}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # Count how many engines flagged it as malicious or suspicious
            malicious = data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            suspicious = data["data"]["attributes"]["last_analysis_stats"].get("suspicious", 0)
            return malicious, suspicious
        else:
            print(f"[-] Error {resp.status_code} for IP {ip}")
            return None, None
    except Exception as e:
        print(f"[-] Exception for IP {ip}: {e}")
        return None, None

# Real-time capture and analysis
def real_time_capture(api_key, checked=None):
    print(f"with API key {api_key}")

    ip_queue = deque()       # Queue for IPs to process
    API_CALL_INTERVAL = 60 / 4  # 4 requests per minute
    last_call = 0

    cap = pyshark.LiveCapture(interface='Ethernet')  
    for packet in cap.sniff_continuously():
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            print(f"Source: {src_ip} -> Destination: {dst_ip}")


            if src_ip not in checked:
               
                ip_queue.append(src_ip)
                checked.add(src_ip)
               

            elif dst_ip not in checked:
                
                ip_queue.append(dst_ip)
                checked.add(dst_ip)
            
            # Queue IP addresses because of VirusTotal rate limiting
            while ip_queue:
                ip = ip_queue.popleft()
                now = time.time()
                elapsed = now - last_call
                if elapsed < API_CALL_INTERVAL:
                    time.sleep(API_CALL_INTERVAL - elapsed)

                mal,sus = check_ip_virustotal(ip, api_key)
                print(f"IP: {ip} → malicious={mal}, suspicious={sus}")
                last_call = time.time()
                
            



# Load Wireshark CSV
def run_vt_check(api_key,csv_file):
    df = pd.read_csv(csv_file)

    # Select the "Address" column
    ip_series = df["Address"]

    # Collect all unique IPs
    ips = set(ip_series.dropna().astype(str).tolist())
    print(f"[+] Found {len(ips)} unique IP addresses")
    results = []
    for idx, ip in enumerate(ips):
        malicious, suspicious = check_ip_virustotal(ip, api_key)
        results.append({"ip": ip, "malicious": malicious, "suspicious": suspicious})
        print(f"[{idx+1}/{len(ips)}] {ip} → malicious={malicious}, suspicious={suspicious}")
        time.sleep(16)  # avoid free API rate limit (4 requests/min)
        # Save results
    results_df = pd.DataFrame(results)
    results_df.to_csv(OUTPUT_FILE, index=False)
    print(f"[+] Done. Results saved to {OUTPUT_FILE}")






def get_output_df():
    # Check if vt_results.csv exists

    if os.path.exists(OUTPUT_FILE):
        df = pd.read_csv(OUTPUT_FILE)
        # Filter out rows where both malicious and suspicious are zero or None
        filtered_df = df[(df["malicious"] > 0) | (df["suspicious"] > 0)]
        # Sort them in descending order by total malicious and suspicious counts
        filtered_df = filtered_df.sort_values(by=["malicious", "suspicious"], ascending=False)
        
    else:
        print(f"[-] {OUTPUT_FILE} not found")
        return pd.DataFrame(columns=["ip", "malicious", "suspicious"])

    return filtered_df

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
 
def index():
    
    if request.method == 'POST':
        user_string = request.form.get('user_string', '')
        app.logger.info(f"Received string: {user_string}")
        api_key = user_string
        uploaded_file = request.files.get('csv_file')
        if uploaded_file and uploaded_file.filename != '':
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
            uploaded_file.save(file_path)
            try:
                df = pd.read_csv(file_path)
                rows = df.shape[0]
            except Exception as e:
                rows = f"Error reading CSV: {e}"
        else:
            file_path = None
            rows = "No file uploaded"

        df_html = get_output_df().to_html(classes='data', header=True, index=False)

        return f"""
        <h3>Received string: {user_string}</h3>
        <h3>Number of rows in uploaded CSV: {rows}</h3>
        <h3>Uploaded file: {uploaded_file.filename if uploaded_file else 'None'}</h3>
        <h3>IP addresses flagged as malicious or suspicious:</h3>
        {df_html}
        <br><br>
        <a href="/live_monitor?api_key={user_string}"><button>Start Live Traffic Monitoring</button></a>


        """
    return render_template('form.html')

# Live monitoring route
@app.route('/live_monitor')
def live_monitor():
    api_key = request.args.get('api_key')
    if not api_key:
        return "API key not set. Submit the form first.", 400
        

    def generate():


        ip_queue = deque()       # Queue for IPs to process
        API_CALL_INTERVAL = 60 / 4  # 4 requests per minute
        last_call = 0
        checked = set()
        yield f"data: Starting live capture with API key {api_key}\n\n"
        asyncio.set_event_loop(asyncio.new_event_loop())  # create a loop in this thread
        cap = pyshark.LiveCapture(interface='Ethernet')  
        for packet in cap.sniff_continuously():
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst


                if src_ip not in checked:
                
                    ip_queue.append(src_ip)
                    checked.add(src_ip)
                

                elif dst_ip not in checked:
                    
                    ip_queue.append(dst_ip)
                    checked.add(dst_ip)
                
                # Queue IP addresses because of VirusTotal rate limiting
                while ip_queue:
                    ip = ip_queue.popleft()
                    now = time.time()
                    elapsed = now - last_call
                    if elapsed < API_CALL_INTERVAL:
                        time.sleep(API_CALL_INTERVAL - elapsed)

                    mal,sus = check_ip_virustotal(ip, api_key)
                    if mal is not None:
                        yield f"data: IP: {ip} → malicious={mal}, suspicious={sus} ------ ALERT ------- \n\n"
                    else:
                        yield f"IP: {ip} → malicious={mal}, suspicious={sus} \n\n"
                    last_call = time.time()
      
    return Response(generate(), mimetype='text/event-stream')

if __name__ == "__main__":
    app.run(debug=True)


    





    