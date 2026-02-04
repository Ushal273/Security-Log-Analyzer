
#Author : Ushal Koirala
#Date: 1/10.2026
#Version: PC:01
#Program: Security Log Analyzer
#Purpose: This Python program reads server log files, detect suspicious activity such as failed
#         logins, access to restricted URLS, and brute-force attempts. It stores these events in
#         a SQLite Database, generates a summary report with charts, and produces an Excel file for 
#         detailed analysis.


"""
AI Use Declaration:
This program was developed with the assistance of generative AI tools (ChatGPT)
used only as a co-pilot for programming support.
AI assistance was limited to code structuring and logic refinement.
All code was reviewed, tested, and verified by the author, who takes
full responsibility for the correctness and functionality of the program.
"""




import os
import json
import sqlite3
import argparse
import requests
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress
from datetime import datetime,timedelta
from collections import defaultdict

DB_FILE = "security_analytics.db" #Database file to store events
RULE_FILE = "rules.json"  #JSON file containing rules

def init_db():
    #Creating Database table to store security events
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT,
                    action TEXT,
                    rule_triggered TEXT,
                    severity TEXT,
                    country TEXT,
                    isp TEXT
                )
    """)
    conn.commit()
    conn.close()

#Cache to avoid repetation of API calls for same IP
geo_cache = {}

def get_geoip(ip):
    #Getting the country and ISP for a given IP address
    if ip in geo_cache:
        return geo_cache[ip]
    
    try:
        #Checking IP if it belongs to a private network
        if ipaddress.ip_address(ip).is_private:
            geo_cache[ip] = ("Internal", "Local Network")
            return geo_cache[ip]
        
        #Calling external API to get IP Location info
        r = requests.get(f"http://ip-api.com/json/{ip}",timeout=3).json()
        if r.get("status") == "success":
            geo_cache[ip] = (r.get("country","Unknown"), r.get("isp","Unknown"))
            return geo_cache[ip]
    
    except:
        #Any failure, timeout, invalid IP, API error falls through
        pass
    
    #Default fallback when lookup falls
    geo_cache[ip] = ("Unknown", "Unknown") #If API fails or times out
    return geo_cache[ip]

def parse_logs(file_paths):
    #Reading log files and converting each line into structured record
    logs = []
    
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Warning: {file_path} not found")
            continue
        
        with open(file_path,"r") as f:
            for line_no, line in enumerate(f,1):
                if "|" not in line:
                    continue
                
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 4:
                    continue
                
                try:
                    ts = datetime.strptime(parts[0],"%Y-%m-%d %H:%M:%S")
                except ValueError:
                    #Ignoring Invalid timestamp formats
                    continue
                
                logs.append({
                    "source_file": os.path.basename(file_path), #File where log came from
                    "line": line_no, #Line number in the file
                    "ts": ts,      
                    "ip": parts[1],
                    "action": parts[2],
                    "status": parts[3]
                })
                
    print(f"Parsed {len(logs)} log entries from {len(file_path)} file.")
    return logs
    

def analyze_logs(logs,rules):
    #Analyzing and detecting Suspicious Events
    if not logs:
        print("No logs to Analyze.")
        return
    
    flagged = []   #List of suspicious events
    failed_logins_times = defaultdict(list) #Tracking failed login timestamps for each IP
    failed_logins_count = defaultdict(int) #Counting failed logins per IP
    simple_flagged_ips = set()  #Keeping track of IPs already flagged for simple rule
    
    #Loading Rule Configuration with safe defaults
    restricted_urls = rules.get("RESTRICTED_URLS",{}).get("urls",["/admin","/config"])
    restricted_sev = rules.get("RESTRICTED_URLS", {}).get("severity", "High")
    brute_thresh = int(rules.get("FAILED_LOGIN_THRESHOLD", {}).get("count", 3))
    brute_window = int(rules.get("FAILED_LOGIN_THRESHOLD",{}).get("time_window_minutes",5))
    brute_sev = rules.get("FAILED_LOGIN_THRESHOLD",{}).get("severity","High")
    simple_thresh = int(rules.get("FAILED_LOGIN_SIMPLE",{}).get("count",3))
    simple_sev = rules.get("FAILED_LOGIN_SIMPLE",{}).get("severity","Medium")
    
    print("\n----- Suspicious Entry------")
    
    #Checking each log entry
    for entry in logs:
        ip = entry["ip"]
        action = entry["action"]
        status = entry["status"]
        
        #Checking restricted URLs
        for url in restricted_urls:
            if url in action:
                flagged.append({"ts":entry["ts"],
                                "ip":ip,
                                "action":action,
                                "rule":"RESTRICTED_ACCESS",
                                "sev":restricted_sev
                                })
                print(f" {entry['source_file']} Line {entry['line']} | {ip} accessed restricted URL: {action}")
                break
        
        #Checking Failed Logins
        if "LOGIN" in action.upper() and status.upper() == "FAILED":
            failed_logins_times[ip].append(entry["ts"])
            failed_logins_count[ip] += 1
            
            #Flag if simple failed loggin rule is exceeded
            if failed_logins_count[ip] > simple_thresh and ip not in simple_flagged_ips:
                simple_flagged_ips.add(ip)
                flagged.append({
                    "ts":entry["ts"],
                    "ip":ip,
                    "action":action,
                    "rule": "FAILED_LOGIN_SIMPLE",
                    "sev": simple_sev
                })
                print(f" {entry['source_file']} Line {entry['line']} | {ip} exceed {simple_thresh} failed logins simple.")
    
    #Checking brute-force attempts
    for ip,times in failed_logins_times.items():
        times.sort()
        for i in range(len(times) - brute_thresh + 1):
            start_time = times[i]
            end_time = times[i + brute_thresh - 1]
            
            #Checking if failed attempts accured within time window
            if end_time - start_time <= timedelta(minutes=brute_window):
                flagged.append({
                    "ts":start_time,
                    "ip":ip,
                    "action":"LOGIN",
                    "rule":"BRUTE_FORCE",
                    "sev":brute_sev
                })
                print(f" Brute-Force Detected: {ip} exceed {brute_thresh} attempts within {brute_window} minutes.")
     
                
    total_failed_attempts = sum(failed_logins_count.values())
    suspicious_ips = {ev["ip"] for ev in flagged}
    
    print(f"Total Failed Login Attempts: {total_failed_attempts}")
    print(f"Suspicious IPs flagged: {len(suspicious_ips)}")
    print(f"Total Flagged Evebts: {len(flagged)}")  
    
    
    #Saving Flagged events to databse
    if flagged:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        for ev in flagged:
            country,isp = get_geoip(ev["ip"])
            cur.execute("""
                        INSERT INTO security_events (
                            timestamp,
                            ip,
                            action,
                            rule_triggered,
                            severity,
                            country,
                            isp
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ev["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                            ev["ip"], 
                            ev.get("action",""),
                            ev["rule"],
                            ev["sev"],
                            country,
                            isp
                        )
            ) 
        conn.commit()
        conn.close()
        print(f"Stored {len(flagged)} events in {DB_FILE}.")


def generate_report():
    if not os.path.exists(DB_FILE):
        print("No Database Found")
        return
    
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql("SELECT * FROM security_events",conn)
    conn.close()
    
    if df.empty:
        print("No suspicious activity to report.")
        return
    
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    print(f"Total Security events: {len(df)}")
    
    print("\nTop 10 Suspicious IPs: ")
    print(df["ip"].value_counts().head(10))
    
    print("\nMost Targeted Actions/URLs: ")
    print(df["action"].value_counts().head(10))
    
    print("\nSeverity Breakdown:")
    print(df["severity"].value_counts())
    
    print("\nRule Breakdown:")
    print(df["rule_triggered"].value_counts())
    
    #Creating trend chart
    plt.figure(figsize=(10,5))
    (df.set_index("timestamp").resample("h").size().plot(kind="line", marker = "s", color = "darkred"))
    plt.title("Security Incident Trend")
    plt.ylabel("Incident Count")
    plt.grid(True, linestyle="--")
    plt.tight_layout()
    plt.savefig("SecurityTrend.png")
    plt.show()
    
    #Saving Excel Report
    try:
        with pd.ExcelWriter("SecurityReport.xlsx", engine="openpyxl") as writer:
            df.to_excel(writer,index=False, sheet_name="All_Events")
            trend_df = (df.set_index("timestamp").resample("h").size().reset_index())
            trend_df.columns= ["Timestamp","Incident-Count"]
            trend_df.to_excel(writer,index=False, sheet_name="Trend_Over_Time")
            ip_summary = df.groupby("ip")["rule_triggered"].value_counts().unstack(fill_value=0)
            ip_summary["Total"] = ip_summary.sum(axis=1)
            ip_summary.sort_values(by="Total", ascending=False, inplace=True)
    
    except Exception as e:
        print (f"Failed Excel Report: {e}")
    

def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("--log", nargs="+", default=["logs.txt"], help="Log Files")
    parser.add_argument("--rules", default=RULE_FILE, help="Rules File")
    args = parser.parse_args()
    
    if not os.path.exists(args.rules):
        print(f"Error: {args.rules} required")
        return
    
    init_db() #Creating database if needed
    with open(args.rules, "r") as f:
        rules = json.load(f)
    
    logs = parse_logs(args.log) #Reading logs from files
    analyze_logs(logs,rules)  #Detecting suspicious events
    generate_report()     #Creating charts and Excel reports
    
if __name__ == "__main__":
    main()
    
            
                        