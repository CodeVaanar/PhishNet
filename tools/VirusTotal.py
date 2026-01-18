'''
Date - 08 - 12 - 2025
Aurthor - CodeVanaar
'''


import requests
import time
import os 
from dotenv import load_dotenv

load_dotenv()


#stores the API key for VirusTotal
API_Key = os.getenv("VT_API_KEY")


#url is taken to VirusTotal API endpoint 
def take_url_to_vt(url):

    submit_endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey" : API_Key
    }

    data = {
        "url" : url 
    }

    response = requests.post(submit_endpoint, headers=headers, data=data)

    if response.status_code != 200:
        return None

    json_data = response.json()

    analysis_id = json_data["data"]["id"]

    return analysis_id


def get_result_from_vt(url):

    analysis_id = take_url_to_vt(url)

    headers = {
        "x-apikey" : API_Key
    }

    start_time = time.time()
    TIMEOUT = 120
    POLL_INTERVAL = 15
    end_time = start_time + TIMEOUT

    while time.time() < end_time:
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",headers = headers)

        if result.status_code != 200:
            return None 
        
        json_result = result.json()

        status = json_result["data"]["attributes"]["status"]
        if status == "completed":
            return json_result
        
        time.sleep(POLL_INTERVAL)
    return None



def extract_summary_vt(url):
    result_json = get_result_from_vt(url)

    stats = result_json["data"]["attributes"]["stats"]

    summary_vt = {
        "malicious" : stats.get("malicious",0),
        "suspicious" : stats.get("suspicious",0),
        "undetected" : stats.get("undetected", 0)
    }

    return summary_vt

def evaluate_summary_vt(url):

    summary_vt = extract_summary_vt(url)

    if not summary_vt:
        return {
            "status": "unknown",
            "reason": "VirusTotal analysis data not available"
        }
    
    malicious = summary_vt.get("malicious", 0)
    suspicious = summary_vt.get("suspicious", 0)


    if malicious > 0:
        return {
            "status": "malicious",
            "reason": f"{malicious} security engines flagged this URL as malicious"
        }

    if suspicious > 0:
        return {
            "status": "suspicious",
            "reason": f"{suspicious} security engines flagged this URL as suspicious"
        }

    return {
        "status": "clean",
        "reason": "No security engines reported malicious or suspicious activity"
    }

