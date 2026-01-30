```
  ========================================================
      _____                      _____                      _   
     |  _  |                    /  ___|                    | |  
     | |_| | _ __    ___ __  __ \ `--.   ___  ___   _   _  | |_ 
     |  _  || '_ \  / _ \\ \/ /  `--. \ / __|/ _ \ | | | | | __|
     | | | || |_) ||  __/ >  <  /\__/ /| (__| (_) || |_| | | |_ 
     \_| |_/| .__/  \___|/_/\_\ \____/  \___|\___/  \__,_|  \__|
            | |                                                 
            |_|         [ Phase: Backend Development ]
    ========================================================
 ```

# Apex-Scout
ApexScout is a lightweight, modular vulnerability scanner built in Python. It is designed to automate the reconnaissance and detection phases of web security testing, specifically focusing on the OWASP Top 10.  


## 🛠 Current Features
- **Phase 1: Recon** - Automated crawling and entry-point discovery.
- **Phase 2: SQLi Engine** - Error-based detection for URLs and Forms.
- **Phase 3: Blind SQLi** - Time-based baseline analysis for silent injections.
- **API Driven** - Fully controlled via REST endpoints (Flask).
- **Clean CLI** - Structured terminal reporting with phase-by-phase updates.

## 📂 Project Structure

```text
Apex-Scout/
├── backend/
│   ├── scanner/
│   │   ├── crawler.py           # Recon & site mapping
│   │   ├── sqli_scanner.py      # Error-based logic
│   │   ├── blind_sqli_scanner.py# Time-delay analysis
│   │   └── scanner_engine.py    # Orchestrates the 3 phases
│   ├── utils/
│   │   └── helpers.py           # ASCII banner & form extractors
│   ├── app.py                   # Flask API routes
│   └── requirements.txt         # Project dependencies
├── frontend/                    # (Future React dashboard)
└── README.md
```
🚦 Quick Start
Clone the repo:

```text
git clone https://github.com/yourusername/ApexScout.git
```

Install dependencies:

```text
pip install -r requirements.txt

```
Run the engine:

```text
python app.py
Trigger a scan: Send a POST request to /scan with {"url": "http://example.com"} using Postman or cURL.
```
