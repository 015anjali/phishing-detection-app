import streamlit as st
import joblib
import pandas as pd
from feature import FeatureExtraction
from pymongo import MongoClient
from datetime import datetime
import requests, time

# Load model
model = joblib.load("phishing_model_structured.pkl")

# MongoDB setup
client = MongoClient("mongodb+srv://phishuser:Phish1234@cluster0.0l0d6pz.mongodb.net/?retryWrites=true&w=majority")
db = client["phishingDB"]
logs = db["prediction_logs"]

# VirusTotal function
def check_with_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    data = {"url": url}
    try:
        resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        scan_id = resp.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

        for _ in range(10):
            result = requests.get(report_url, headers=headers).json()
            if result["data"]["attributes"]["status"] == "completed":
                stats = result["data"]["attributes"]["stats"]
                if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                    return "🔴 Malicious (VirusTotal)"
                else:
                    return "🟢 Safe (VirusTotal)"
            time.sleep(1)
    except:
        return "❌ API Error"
    return "⚠️ Timeout"

# UI
st.title("🔍 Phishing URL Detector (Hybrid)")
url_input = st.text_input("Enter a URL")

if st.button("Check URL") and url_input:
    existing = logs.find_one({"url": url_input})
    if existing:
        st.info("🔁 Cached Result")
        st.write(f"Model: {existing['model_verdict']}")
        st.write(f"VirusTotal: {existing['vt_result']}")
        st.write(f"Final Verdict: {existing['final_verdict']}")
    else:
        features = FeatureExtraction(url_input).getFeaturesList()
	
        print("FEATURES:", features)
        print("TYPE:", type(features))

        feature_names = [
           'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-', 'SubDomains',
           'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
           'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding',
           'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain',
           'DNSRecording', 'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
        ]


        input_df = pd.DataFrame([features], columns=feature_names)
        pred = model.predict(input_df)[0]
        model_verdict = "🔴 Phishing" if pred == 1 else "🟢 Legitimate"
        vt_result = check_with_virustotal(url_input, "3d80d1619eafcd513fe9e2cf00b5072a319da97e1f694482a1401337748d802f")
        final = "🔴 Phishing" if "Malicious" in vt_result or pred == 1 else "🟢 Legitimate"

        logs.insert_one({
            "url": url_input,
            "model_verdict": model_verdict,
            "vt_result": vt_result,
            "final_verdict": final,
            "timestamp": datetime.utcnow()
        })

        st.success("✅ Scanned")
        st.write(f"Model: {model_verdict}")
        st.write(f"VirusTotal: {vt_result}")
        st.write(f"Final Verdict: {final}")
