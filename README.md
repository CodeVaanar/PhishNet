<img width="2912" height="1440" alt="phishnet" src="https://github.com/user-attachments/assets/3245692a-fdbc-4925-923a-6f229344f7ca" />

 
PhishNet is a lightweight, Flask-based security tool that checks suspicious URLs in real time. It uses trusted security services like VirusTotal and urlscan.io to help identify risks such as phishing websites, malware, and social engineering attacks.

The goal of PhishNet is to provide clear results in one place, without requiring users to manually check multiple security platforms.

## Features

1. Multi-Engine URL Analysis - PhishNet sends a URL to multiple security services and combines their results into a single, easy-to-understand report.
     - VirusTotal checks the URL against many antivirus engines and blocklists.
     - urlscan.io analyzes how the website behaves and captures a screenshot.

2. Faster Scans - Multiple scans run at the same time, reducing the overall waiting time for results.

4. Website Screenshot Preview -  Displays a screenshot of the scanned website so users can view it safely without opening the link directly.

5. Modular Backend - The backend is easy to extend and can be connected with other tools in the future easily.

## Prerequisites

1. Working Environment
   - Backend:
       - Python Version : 3.11.0 or higher
       - Download link : https://www.python.org/downloads/
       - Ensure that Python and pip are added to your system:
         - python --version
         - pip --version
    - Frontend:
        - HTML5 & CSS3: No installation required (standard web technologies).
        - JavaScript: Runs natively in the browser.
        - Browser: A modern web browser (Chrome, Firefox, Edge, or Safari) is required to be able the UI.
     
2. Required python libraries
   - pip install flask
   - pip install requests
   - pip install python-dotenv
      
## Installation
- Clone the repository :
    - git clone https://github.com/CodeVaanar/PhishNet
    - cd PhishNet
- Configure API Keys:
    - PhishNet requires API keys from the following services:
        - VirusTotal (https://www.virustotal.com/gui/home/upload): Create an API key from your VirusTotal account.
        - urlscan.io (https://urlscan.io/): Generate an API key from your urlscan.io dashboard.
    - Rename the .env.example file to .env and add your own API keys in the appropriate fields.

- Run the Application
    - python app.py
    - After the server starts, copy the local URL displayed in the terminal and open it in your web browser.
      
## Glimpse
<img width="679" height="278" alt="Screenshot 2026-01-19 201152" src="https://github.com/user-attachments/assets/129396fa-6599-46e9-b610-f3d419479311" />

<img width="698" height="605" alt="Screenshot 2026-01-19 201140" src="https://github.com/user-attachments/assets/a1a78a81-2017-472e-8b83-365a0b0321f8" />
