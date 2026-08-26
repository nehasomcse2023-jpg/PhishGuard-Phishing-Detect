# Deloitte Interview Guide — PhishGuard

## 60-second explanation
"I built PhishGuard, a phishing awareness and URL risk detection web application. The user submits a URL, the system extracts security-relevant lexical features such as HTTPS usage, URL length, IP-address hosts, suspicious keywords, URL shorteners and punycode, and then calculates an explainable risk score. The application returns Low, Medium or High risk along with the reasons. I chose an explainable approach because security analysts need to understand why an alert was generated. For production, I would combine this with threat-intelligence, DNS/reputation and email-context signals and monitor false positives and false negatives."

## Architecture
Browser -> Flask -> URL parser -> feature extraction -> risk scoring -> explanation -> browser

## Questions you should be ready for
1. What is phishing?
2. Difference between phishing, spear phishing and whaling?
3. Why is HTTPS not proof that a website is safe?
4. Why can an IP address in a URL be suspicious?
5. What are false positives and false negatives?
6. Which metric matters for phishing detection and why?
7. How would you improve this system?
8. How would you deploy it?
9. How would you protect the API from abuse?
10. What would you log in a SOC environment?
11. How would you integrate a threat-intelligence feed?
12. Why did you make the result explainable?

## Strong answer for "How would you improve it?"
"I would build a labeled dataset, add domain-age/DNS/WHOIS-style features where legally and operationally appropriate, integrate reputation and threat-intelligence feeds, compare Random Forest/XGBoost with calibrated probabilities, tune the decision threshold for the business cost of false negatives, and continuously monitor drift."

## Important honesty rule
Do not say this demo uses a Random Forest unless you actually train and ship a Random Forest model. This ZIP uses an explainable heuristic detector so you can understand every line of the implementation.

## Suggested resume line
"Built a Flask-based phishing URL awareness and risk-detection tool using explainable URL lexical features, risk scoring, and security-awareness guidance."
