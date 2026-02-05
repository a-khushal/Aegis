#!/usr/bin/env python3
import requests
import time
import sys

WAF_URL = "http://localhost:8000"
BACKEND_URL = "http://localhost:9000"

def test_request(url, description, expected="allowed"):
    try:
        response = requests.get(url, timeout=5)
        status = response.status_code
        content = response.text[:100]
        
        if expected == "allowed":
            result = "✓" if status == 200 else "✗"
        else:
            result = "✓" if status in [403, 429] or "blocked" in content.lower() or "banned" in content.lower() else "✗"
        
        print(f"{result} {description}")
        print(f"   Status: {status}")
        print(f"   Response: {content}")
        print()
        return status
    except Exception as e:
        print(f"✗ {description} - Error: {e}")
        print()
        return None

def test_post(url, data, description, expected="allowed"):
    try:
        response = requests.post(url, data=data, timeout=5)
        status = response.status_code
        content = response.text[:100]
        
        if expected == "allowed":
            result = "✓" if status == 200 else "✗"
        else:
            result = "✓" if status in [403, 429] or "blocked" in content.lower() else "✗"
        
        print(f"{result} {description}")
        print(f"   Status: {status}")
        print(f"   Response: {content}")
        print()
        return status
    except Exception as e:
        print(f"✗ {description} - Error: {e}")
        print()
        return None

print("=" * 60)
print("WAF Comprehensive Test Suite")
print("=" * 60)
print()

print("1. Testing Normal Requests (Should be ALLOWED)")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=hello", "Normal search query")
test_request(f"{WAF_URL}/search?q=world", "Normal search query 2")
test_request(f"{WAF_URL}/search?q=test123", "Normal search query 3")
time.sleep(0.5)

print("2. Testing SQL Injection Attacks (Should be BLOCKED)")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=' OR 1=1--", "SQL Injection: OR 1=1", expected="blocked")
test_request(f"{WAF_URL}/search?q=' OR '1'='1", "SQL Injection: OR '1'='1", expected="blocked")
test_request(f"{WAF_URL}/search?q=union select", "SQL Injection: UNION SELECT", expected="blocked")
test_request(f"{WAF_URL}/search?q=sleep(5)", "SQL Injection: sleep()", expected="blocked")
test_request(f"{WAF_URL}/search?q=benchmark(1000000,md5('test'))", "SQL Injection: benchmark()", expected="blocked")
time.sleep(0.5)

print("3. Testing XSS Attacks (Should be BLOCKED)")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=<script>alert('xss')</script>", "XSS: <script> tag", expected="blocked")
test_request(f"{WAF_URL}/search?q=<img src=x onerror=alert('xss')>", "XSS: onerror handler", expected="blocked")
test_request(f"{WAF_URL}/search?q=javascript:alert('xss')", "XSS: javascript: protocol", expected="blocked")
test_request(f"{WAF_URL}/search?q=document.cookie", "XSS: document.cookie", expected="blocked")
test_request(f"{WAF_URL}/search?q=<body onload=alert('xss')>", "XSS: onload handler", expected="blocked")
time.sleep(0.5)

print("4. Testing Command Injection Attacks (Should be BLOCKED)")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=; rm -rf /", "Command Injection: rm -rf", expected="blocked")
test_request(f"{WAF_URL}/search?q=|| ls", "Command Injection: || ls", expected="blocked")
test_request(f"{WAF_URL}/search?q=| cat /etc/passwd", "Command Injection: cat /etc/passwd", expected="blocked")
test_request(f"{WAF_URL}/search?q=`whoami`", "Command Injection: backticks", expected="blocked")
test_request(f"{WAF_URL}/search?q=$(whoami)", "Command Injection: $()", expected="blocked")
time.sleep(0.5)

print("5. Testing POST Requests with Attacks")
print("-" * 60)
test_post(f"{WAF_URL}/login", {"username": "admin", "password": "password"}, "POST: Normal login", expected="allowed")
test_post(f"{WAF_URL}/login", {"username": "' OR 1=1--", "password": "anything"}, "POST: SQL Injection in login", expected="blocked")
test_post(f"{WAF_URL}/login", {"username": "<script>alert('xss')</script>", "password": "test"}, "POST: XSS in login", expected="blocked")
time.sleep(0.5)

print("6. Testing Different Endpoints")
print("-" * 60)
test_request(f"{WAF_URL}/admin", "Admin endpoint")
test_request(f"{WAF_URL}/login", "Login endpoint")
test_request(f"{WAF_URL}/nonexistent", "Non-existent endpoint")
time.sleep(0.5)

print("7. Testing Rate Limiting (Sending 15 requests rapidly)")
print("-" * 60)
print("Sending 15 requests to trigger rate limit...")
blocked_count = 0
for i in range(1, 16):
    status = test_request(f"{WAF_URL}/search?q=ratelimit{i}", f"Rate limit test {i}/15")
    if status and status in [403, 429]:
        blocked_count += 1
    time.sleep(0.1)
print(f"Rate limit triggered: {blocked_count} requests blocked")
print()

print("8. Testing Edge Cases")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=normal%20text%20with%20spaces", "URL encoded spaces")
test_request(f"{WAF_URL}/search?q=test&other=param", "Multiple query parameters")
test_request(f"{WAF_URL}/search", "Empty query parameter")
time.sleep(0.5)

print("9. Testing Mixed Payloads")
print("-" * 60)
test_request(f"{WAF_URL}/search?q=hello' OR 1=1--<script>", "Mixed: SQL + XSS", expected="blocked")
test_request(f"{WAF_URL}/search?q=test; rm -rf<script>alert('xss')</script>", "Mixed: Command + XSS", expected="blocked")
time.sleep(0.5)

print("10. Testing Large Payloads")
print("-" * 60)
large_payload = "A" * 1000
test_request(f"{WAF_URL}/search?q={large_payload}", "Large payload (1000 chars)")

print("=" * 60)
print("Test Suite Complete!")
print("=" * 60)
print()
print(f"Check the dashboard at: {WAF_URL}/dashboard")
print(f"Check metrics at: {WAF_URL}/dashboard/metrics")
print(f"Check logs at: {WAF_URL}/dashboard/logs")
print(f"Check bans at: {WAF_URL}/dashboard/bans")
print()

