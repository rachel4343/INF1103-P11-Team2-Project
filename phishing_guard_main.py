import requests
import json
from typing import Dict, Optional, Tuple


API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"
API_KEY = "AIzaSyD-Your-API-Key-Here"


def call_gemini_api(subject: str, body: str, sender: str = ""):
    prompt = f"""
Analyze this email for phishing. Return ONLY valid JSON.

SENDER: {sender}
SUBJECT: {subject}
BODY: {body}

JSON format:
{{
  "threat_level": "low|medium|high|critical",
  "confidence": 0.0 to 1.0,
  "impersonation": true or false,
  "urgency_manipulation": true or false,
  "credential_request": true or false,
  "suspicious_link": true or false,
  "attachment_risk": true or false,
  "attack_type": "credential harvesting|malware delivery|impersonation|suspicious spam|none",
  "explanation": "Brief reason"
}}
"""
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1}
    }

    try:
        
        response = requests.post(
            f"{API_URL}?key={API_KEY}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=60
        )

        if response.status_code == 200:
            data = response.json()
            try:
                result_text = data["candidates"][0]["content"]["parts"][0]["text"]
                result_text = result_text.strip().strip("`").strip()
                return json.loads(result_text), None
            except Exception as e:
                return None, f"Failed to parse result: {str(e)}"

        if response.status_code == 401:
            return None, " Key invalid — try new key from aistudio.google.com"
        if response.status_code == 403:
            return None, " Access denied"
        if response.status_code == 404:
            return None, " Model not found"
        if response.status_code == 429:
            return None, " Too many requests — wait 1 minute"
        return None, f"API Error {response.status_code}"

    except requests.exceptions.ReadTimeout:
        return None, " Slow connection — Google took too long to reply. Try again."
    except requests.exceptions.ConnectionError:
        return None, " No internet connection — check your network"
    except Exception as e:
        return None, f"Error: {str(e)}"

def analyze_email(report: Dict):
    viewed = report.get("viewed", True)

    if not viewed:
        return call_gemini_api(
            "NOT VIEWED",
            f"Reason: {report.get('reason_not_viewed', '')}",
            report.get("sender", "")
        )

    body_text = report.get("body", "")
    links = report.get("links", [])
    if links:
        body_text += f"\nLinks: {', '.join(links)}"

    result, error = call_gemini_api(
        report.get("subject", ""),
        body_text,
        f"{report.get('sender_name', '')} {report.get('sender_email', '')}"
    )

    if error:
        return None, error

    level = result.get("threat_level", "low")
    if level in ("critical", "high"):
        result["recommended_action"] = "Do NOT click links. Report to Security."
    elif level == "medium":
        result["recommended_action"] = "Verify sender through official contact."
    else:
        result["recommended_action"] = "No immediate action."

    return result, None

if __name__ == "__main__":
    print(" Connecting to Gemini API...")
    print(" Please wait up to 60 seconds...\n")
    
    test_report = {
        "viewed": True,
        "sender_name": "IT Support",
        "sender_email": "support@fake.com",
        "subject": "URGENT: Verify Your Account",
        "body": "Click here to enter your password immediately or your account will be locked.",
        "links": ["http://fake-login.com"]
    }
    
    result, error_msg = analyze_email(test_report)
    
    if error_msg:
        print("nothing", error_msg)
    else:
        print(" SUCCESS! Connected to Gemini!")
        print("-" * 40)
        print("Threat Level  :", result.get("threat_level", "UNKNOWN").upper())
        print("Confidence    :", f"{result.get('confidence', 0) * 100:.0f}%")
        print("Attack Type   :", result.get("attack_type", "none"))
        print("Explanation   :", result.get("explanation", "-"))
