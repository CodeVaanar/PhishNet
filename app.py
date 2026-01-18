'''
Date - 02 - 01 - 2026
Aurthor - CodeVanaar
'''

from flask import Flask, request, render_template, make_response
from tools import VirusTotal as vtotal 
from tools import UrlScan as urlS 
import concurrent.futures


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan',methods = ["POST"])
def scan():
    data = request.get_json(silent=True)
    if not data or not data.get("url"):
        return {"error": "No URL provided"}, 400
    url = data.get("url")
    # vt = vtotal.evaluate_summary_vt(url)
    # urlscan = urlS.evaluate_summary_from_urlscan(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers = 2) as executor:
        future_vt = executor.submit(vtotal.evaluate_summary_vt, url)
        future_urlscan = executor.submit(urlS.evaluate_summary_from_urlscan,url)

        try:
            vt = future_vt.result()
        except Exception as e:
            vt = {"status":"error","reason":str(e)}

        try:
            urlscan = future_urlscan.result()
        except Exception as e :
            urlscan = {"status":"error", "reason": str(e)}

    output = {
        "VirusTotal" : vt,
        "UrlScan" : urlscan
    }

    return output 



if __name__ == "__main__":
    app.run(debug=True)