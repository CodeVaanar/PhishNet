# PHISHNET 
PhishNet is a lightweight, Flask-based, multi-engine security tool designed to analyze suspicious URLs in real time. It aggregates threat intelligence from industry leading security services such as VirusTotal and urlscan.io to deliver a comprehensive verdict on potential risks, including phishing attempts, malware distribution, and social engineering attacks.

## Features

1. Multi-Engine URL Analysis - PhishNet submits user-provided URLs to different threat-intelligence services and normalizes their outputs into a single, actionable verdict.
     - VirusTotal — Correlates URL reputation across 60+ antivirus engines and blocklists.
     - urlscan.io — Executes a live behavioral scan, capturing network activity, DOM changes, and a rendered page screenshot.

2. Thread Pool–Based Concurrency - PhishNet utilizes Python’s concurrent.futures.ThreadPoolExecutor to execute multiple URL analysis tasks concurrently. A managed thread pool is used to efficiently handle I/O-bound scanning operations while controlling resource usage.

3. Visual Context Without Exposure -  Retrieves and displays the urlscan.io screenshot, enabling visual inspection of the target page without direct interaction.

4. Unified Security Interface - Designed as a single aggregation layer for multiple security tools, eliminating the need to manually cross-check results across platforms.

5. JSON-First Backend - The Flask backend is built around structured JSON request/response handling, enabling clean API boundaries, easy extensibility, and straightforward frontend or third-party integration.

6. Modular & Extensible Architecture - The codebase follows a modular design, with each scanning engine, utility, and response processor isolated into independent components. This allows new security tools to be integrated with minimal refactoring.

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
        - Browser: A modern web browser (Chrome, Firefox, Edge, or Safari) is required to render the UI.
     
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
      
