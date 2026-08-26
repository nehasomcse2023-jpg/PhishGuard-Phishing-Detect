import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "confirm", "bank", "wallet", "free", "bonus",
    "urgent", "recover", "reset"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly"
}

def extract_features(url: str):
    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    p = urlparse(candidate)
    host = (p.netloc or "").lower().split("@")[-1].split(":")[0]
    path = (p.path or "").lower()
    full = candidate.lower()

    return {
        "https": int(p.scheme == "https"),
        "url_length": len(url),
        "host_length": len(host),
        "dots": host.count("."),
        "hyphens": host.count("-"),
        "at_symbol": int("@" in url),
        "ip_address": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "double_slash_path": int("//" in path),
        "query_params": int(bool(p.query)),
        "suspicious_words": sum(1 for w in SUSPICIOUS_WORDS if w in full),
        "shortener": int(host in SHORTENERS),
        "punycode": int("xn--" in host),
        "subdomains": max(0, host.count(".") - 1),
    }

def analyze_url(url: str):
    f = extract_features(url)
    score = 0
    reasons = []

    if not f["https"]:
        score += 15
        reasons.append("The URL does not use HTTPS.")
    if f["url_length"] > 75:
        score += 12
        reasons.append("The URL is unusually long.")
    if f["at_symbol"]:
        score += 25
        reasons.append("The URL contains '@', which can hide the real destination.")
    if f["ip_address"]:
        score += 25
        reasons.append("The hostname is an IP address rather than a normal domain.")
    if f["hyphens"] >= 3:
        score += 10
        reasons.append("The hostname contains several hyphens.")
    if f["subdomains"] >= 3:
        score += 10
        reasons.append("The URL contains multiple subdomains.")
    if f["suspicious_words"] >= 2:
        score += 18
        reasons.append("It contains multiple words commonly used in phishing lures.")
    elif f["suspicious_words"] == 1:
        score += 8
        reasons.append("It contains a word commonly used in phishing lures.")
    if f["shortener"]:
        score += 15
        reasons.append("It uses a URL-shortening service.")
    if f["punycode"]:
        score += 20
        reasons.append("The domain uses punycode, which can be associated with look-alike domains.")
    if f["double_slash_path"]:
        score += 10
        reasons.append("The path contains a second '//' pattern.")

    score = min(score, 100)
    if score >= 50:
        label = "Likely Phishing"
        risk = "High"
    elif score >= 25:
        label = "Suspicious"
        risk = "Medium"
    else:
        label = "Likely Legitimate"
        risk = "Low"

    if not reasons:
        reasons.append("No major heuristic indicators were detected.")

    return {"label": label, "risk": risk, "score": score, "reasons": reasons, "features": f}
