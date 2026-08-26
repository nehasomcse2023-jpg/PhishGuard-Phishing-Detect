from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from detector import analyze_url

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = analyze_url(url)
    return render_template("index.html", result=result, url=url)

# --- NEW API ROUTE FOR EXTENSION ---
@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    data = request.get_json() or {}
    url = data.get('url', '')
    
    result = analyze_url(url) if url else {}
    is_phishing = result.get("risk_level") == "High"
    
    return jsonify({
        "url": url,
        "is_phishing": is_phishing,
        "risk_score": result.get("score", 0),
        "status": result.get("label", "Unknown")
    })

if __name__ == "__main__":
    app.run(debug=True)
