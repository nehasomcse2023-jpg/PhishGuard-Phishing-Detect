# PhishGuard — Phishing Awareness & URL Risk Detection

## Project objective
A safe educational web application that analyzes a URL using explainable phishing heuristics and produces a Low/Medium/High risk result.

## Technology
- Python
- Flask
- HTML/CSS
- URL parsing and lexical security features

## Run on Windows
1. Install Python 3.11 or newer.
2. Extract this ZIP.
3. Open the extracted folder in VS Code.
4. Open Terminal in the project folder.
5. Create a virtual environment:
   `python -m venv venv`
6. Activate it:
   `venv\Scripts\activate`
7. Install dependencies:
   `pip install -r requirements.txt`
8. Start:
   `python app.py`
9. Open the address shown in the terminal, normally `http://127.0.0.1:5000`.

## Demo URLs
Try:
- https://www.google.com
- https://www.microsoft.com
- http://secure-login-example.com/verify
- http://192.168.1.10/login
- http://bit.ly/verify-account

Do not visit suspicious URLs. Paste them into the analyzer as text only.

## How the detector works
It extracts explainable URL features such as HTTPS usage, length, IP-host usage, '@' symbols, suspicious keywords, URL shorteners, punycode, subdomains and hyphens. A weighted heuristic score maps to Low/Medium/High risk.

## Interview note
This version intentionally avoids claiming that a small demo model can guarantee phishing detection. In a production system, combine lexical features with threat-intelligence feeds, reputation data, DNS/domain-age signals, email context, sandboxing and continuous model evaluation.
