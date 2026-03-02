import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================= CONFIG =================

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "tinyllama"
ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your_mail"
SMTP_PASSWORD = "your_passwd"
RECEIVER_EMAIL = "your_mail"

AI_MIN_RULE_LEVEL = 3   # Only alerts with level >= 3 are analyzed by AI

# ================= READ LAST ALERT =================

def get_last_alert():
    # Read the last line of alerts.json
    with open(ALERT_FILE, "r") as f:
        lines = f.readlines()
        last = json.loads(lines[-1])

    # Truncate long logs to prevent CPU overload
    full_log = last.get("full_log", "")
    if len(full_log) > 300:
        full_log = full_log[:300] + "..."

    enriched_alert = {
        "timestamp": last.get("timestamp"),
        "agent": last.get("agent", {}).get("name"),
        "rule_id": last.get("rule", {}).get("id"),
        "rule_level": last.get("rule", {}).get("level"),
        "rule_description": last.get("rule", {}).get("description"),
        "src_ip": last.get("data", {}).get("srcip"),
        "dst_user": last.get("data", {}).get("dstuser"),
        "full_log": full_log
    }

    return enriched_alert

# ================= AI ANALYSIS =================

def analyze_alert(alert):

    # Skip low-level alerts to save CPU
    if alert["rule_level"] is None or alert["rule_level"] < AI_MIN_RULE_LEVEL:
        return "Low level alert - AI analysis skipped."

    # Build prompt for AI
    prompt = f"""
You are a professional SOC analyst.

STRICT RULES:
- Use ONLY the real values provided.
- Do NOT use placeholders.
- Do NOT invent information.
- Keep the report under 220 words.
- Ensure Risk Level and Reason are consistent.
- End with a complete sentence.

Respond EXACTLY in this format:

Incident Summary:
Date/Time:
Source IP:
Target Host:
Target User:
Rule Description:

Risk Level:
Reason:

Recommended Action:

Block Source IP? (Yes/No):

Security Alert:
<short log summary>

Security Alert Data:
{alert}
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 280,
            "temperature": 0.2,  # Low temperature for consistent output
            "num_ctx": 2048
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=500)
        data = response.json()

        # Return AI response if present
        if "response" in data:
            return data["response"].strip()
        else:
            return f"AI returned unexpected format: {data}"

    except Exception as e:
        return f"AI Error: {str(e)}"

# ================= EMAIL FUNCTION =================

def send_email(content):

    # Build email message
    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = "Wazuh AI SOC Alert"

    msg.attach(MIMEText(content, "plain"))

    try:
        # Connect to SMTP and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Email sending error:", e)

# ================= MAIN =================

if __name__ == "__main__":

    print("Reading the last alert...")
    alert = get_last_alert()

    print("AI is analyzing the alert...")
    ai_result = analyze_alert(alert)

    print("\n===== AI ANALYSIS =====\n")
    print(ai_result)

    # Send AI report via email
    send_email(ai_result)
