import requests
import os

class AlertSystem:
    def __init__(self, token=None, chat_id=None):
        # We look for environment variables or use provided ones
        self.token = token or os.getenv("SENTRY_TELEGRAM_TOKEN")
        self.chat_id = chat_id or os.getenv("SENTRY_TELEGRAM_CHAT_ID")
        self.enabled = self.token is not None and self.chat_id is not None
        
        if not self.enabled:
            print("[!] Telegram Alarms: DISABLED (Missing Token or Chat ID)")
        else:
            print("[+] Telegram Alarms: ENABLED")

    def send_alert(self, message):
        """
        Sends a message to the configured Telegram chat.
        """
        if not self.enabled:
            return False
            
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": f"🚨 SENTRY ALERT 🚨\n\n{message}",
            "parse_mode": "Markdown"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Telegram alert: {e}")
            return False

if __name__ == "__main__":
    # Test block
    test_token = "YOUR_TOKEN"
    test_chat = "YOUR_CHAT_ID"
    alerter = AlertSystem(test_token, test_chat)
    if alerter.enabled:
        alerter.send_alert("Test message from Sentry Security Agent")
