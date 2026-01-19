'''
Date - 19 - 12 - 2025
Author - CodeVaanar
Desc - handles all communication with UrlScan API and handles the results.
'''

import requests
import time
import os 
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("URLSCAN_API_KEY")

def take_url_to_urlscan(url):

    submit_endpoint = "https://urlscan.io/api/v1/scan/"

    headers = {
        "API-Key" : API_KEY,
        "Content-Type": "application/json"
    } 

    data = {
        "url" : url,
        "visibility": "public"
    }

    response = requests.post(submit_endpoint,headers=headers,json = data)
    if response.status_code != 200:           
        return None

    json_data = response.json()

    scan_id = json_data.get("uuid")

    return scan_id



def take_result_from_urlscan(url):

    scan_id = take_url_to_urlscan(url)

    if not scan_id:
        return None 
    
    headers = {
        "API-Key" : API_KEY
    }

    start_time = time.time()
    TIMEOUT = 80
    POLL_INTERVAL = 10
    end_time = start_time + TIMEOUT

    while time.time() < end_time:
        response = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/",headers = headers)

        if response.status_code == 200:
            return response.json()
        
        elif response.status_code == 404:
            pass 

        else:
            return None 
        
        time.sleep(POLL_INTERVAL)
    return None



def extract_summary_from_urlscan(url):
    response = take_result_from_urlscan(url)

    if not response:
        return None

    verdict = response.get("verdict",{}).get("overall",{})
    lists = response.get("lists",{})

    task = response.get("task",{})
    screenshot_url = task.get("screenshotURL")

    result = {
        "malicious": 1 if verdict.get("malicious",False) else 0,
        "score" : verdict.get("score",0),
        "phishing" : 1 if lists.get("phishing",False) else 0,
        "malware" : 1 if lists.get("malware",False) else 0,
        "cryptomining" : 1 if lists.get("cryptomining",False) else 0,
        "screenshot" :screenshot_url
    }

    return result 

def evaluate_summary_from_urlscan(url):

    result = extract_summary_from_urlscan(url)

    if not result:
        return {
            "status" : "unknown",
            "reason" : "no data returned from urlscan",
            "screenshot" : None
        }
    
    screenshot = result.get("screenshot")
    
    if result.get("malicious",0) == 1:
        return {
            "status": "malicious",
            "reason" : "URLscan flagged url as malicious",
            "screenshot" : screenshot
        }
    
    for flag in ["phishing", "malware", "cryptomining"]:
        if result.get(flag,0) == 1:
            return {
                "status" : "malicious",
                "reason" : f"URLscan detected {flag}",
                "screenshot" : screenshot
            }
        
    if result.get("score",0) > 0 :
        return {
            "status" : "suspicious",
            "reason" : "URLscan returned suspicious activity score",
            "screenshot" : screenshot
        }
    
    return{
        "status" : "clean",
        "reason" : "no malicious or suspicious indicators were detected",
        "screenshot" : screenshot
    }