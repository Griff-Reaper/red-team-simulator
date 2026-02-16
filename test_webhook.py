import os
import json
from urllib.request import Request, urlopen

webhook_url = os.getenv("DISCORD_WEBHOOK")

print(f"Webhook URL: {webhook_url}")
print(f"URL Length: {len(webhook_url) if webhook_url else 0}")

if not webhook_url:
    print("ERROR: DISCORD_WEBHOOK not set!")
    exit()

# Simple test message
payload = {
    "content": "🧪 Test message from Python"
}

data = json.dumps(payload).encode('utf-8')
headers = {'Content-Type': 'application/json'}

try:
    request = Request(webhook_url, data=data, headers=headers)
    response = urlopen(request, timeout=10)
    print(f"✅ Success! Status: {response.status}")
except Exception as e:
    print(f"❌ Error: {e}")