chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId === 0 && details.url.startsWith('http')) {
        try {
            let response = await fetch('http://127.0.0.1:5000/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: details.url })
            });
            
            let result = await response.json();
            
            if (result.is_phishing) {
                alert(`⚠️ PhishGuard Warning!\n\nThis site looks like a Fraud/Phishing link:\n${details.url}`);
            }
        } catch (err) {
            console.error("Backend Error:", err);
        }
    }
});