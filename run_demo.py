import json, sys, urllib.request, os, subprocess

url = "http://localhost:8000/api/v1/agents"
payload = {
    "name": "Demo Agent",
    "framework": "custom",
    "owner": "security@example.com",
    "role": "finance_agent"
}

data = json.dumps(payload).encode('utf-8')
req = urllib.request.Request(url, data=data, method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("x-admin-api-key", "local-demo-admin-key")

with urllib.request.urlopen(req) as resp:
    resp_json = json.load(resp)

agent_id = resp_json.get("id")
api_key = resp_json.get("api_key")

print(f"Registered agent: {agent_id}")
print(f"API key: {api_key}")

# Set environment variables for the demo script
os.environ["AGENT_SENTINEL_AGENT_ID"] = agent_id
os.environ["AGENT_SENTINEL_API_KEY"] = api_key

# Run the demo attack script
result = subprocess.run([sys.executable, "demo/attack_demo.py"], capture_output=True, text=True)
print("--- Demo script output ---")
print(result.stdout)
print(result.stderr, file=sys.stderr)
