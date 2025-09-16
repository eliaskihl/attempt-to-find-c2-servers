import pandas as pd
import requests
import time
import os
from flask import Flask, request, render_template, redirect, url_for


# Output file for results
OUTPUT_FILE = "vt_results.csv"






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
        # Get the text input
        user_string = request.form.get('user_string', '')
        
        # Get the uploaded file
        uploaded_file = request.files.get('csv_file')
        if uploaded_file and uploaded_file.filename != '':
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
            uploaded_file.save(file_path)
            
            # Example: read CSV
            try:
                print(file_path)
                df = pd.read_csv(file_path)
                rows = df.shape[0]
                #run_vt_check(user_string,file_path)
                
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
        """
    return render_template('form.html')

if __name__ == "__main__":
    app.run(debug=True)
# def main():
#     print("Choose option:")
#     print("1. Run VirusTotal IP reputation check")
#     print("2. Print output file contents")
#     print("q. Quit")
#     choice = input("Enter choice: ")

#     match choice:
#         case "1": 
#             print("Enter your VirusTotal API key:")
#             api_key = input().strip()
#             run_vt_check(api_key)
#         case "2":
#             print_output_file()
#         case "q":
#             print("Exiting...")
#             exit(0)
#         case _:
#             print("Invalid choice")


