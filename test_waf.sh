#!/bin/bash

WAF_URL="http://localhost:8000"
BACKEND_URL="http://localhost:9000"

echo "=========================================="
echo "WAF Comprehensive Test Suite"
echo "=========================================="
echo ""

echo "1. Testing Normal Requests (Should be ALLOWED)"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=hello" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=world" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=test123" | head -c 100
echo ""
echo ""

echo "2. Testing SQL Injection Attacks (Should be BLOCKED)"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=' OR 1=1--" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=' OR '1'='1" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=union select" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=sleep(5)" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=benchmark(1000000,md5('test'))" | head -c 100
echo ""
echo ""

echo "3. Testing XSS Attacks (Should be BLOCKED)"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=<script>alert('xss')</script>" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=<img src=x onerror=alert('xss')>" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=javascript:alert('xss')" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=document.cookie" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=<body onload=alert('xss')>" | head -c 100
echo ""
echo ""

echo "4. Testing Command Injection Attacks (Should be BLOCKED)"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=; rm -rf /" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=|| ls" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=| cat /etc/passwd" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=\`whoami\`" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=\$(whoami)" | head -c 100
echo ""
echo ""

echo "5. Testing POST Requests with Attacks"
echo "-------------------------------------------"
curl -s -X POST "$WAF_URL/login" -d "username=admin&password=password" | head -c 100
echo ""
echo ""

curl -s -X POST "$WAF_URL/login" -d "username=' OR 1=1--&password=anything" | head -c 100
echo ""
echo ""

curl -s -X POST "$WAF_URL/login" -d "username=<script>alert('xss')</script>&password=test" | head -c 100
echo ""
echo ""

echo "6. Testing Different Endpoints"
echo "-------------------------------------------"
curl -s "$WAF_URL/admin" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/login" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/nonexistent" | head -c 100
echo ""
echo ""

echo "7. Testing Rate Limiting (Sending 15 requests rapidly)"
echo "-------------------------------------------"
for i in {1..15}; do
    echo -n "Request $i: "
    curl -s "$WAF_URL/search?q=ratelimit$i" | head -c 50
    echo ""
    sleep 0.1
done
echo ""

echo "8. Testing Edge Cases"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=normal%20text%20with%20spaces" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=test&other=param" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search" | head -c 100
echo ""
echo ""

echo "9. Testing Mixed Payloads"
echo "-------------------------------------------"
curl -s "$WAF_URL/search?q=hello' OR 1=1--<script>" | head -c 100
echo ""
echo ""

curl -s "$WAF_URL/search?q=test; rm -rf<script>alert('xss')</script>" | head -c 100
echo ""
echo ""

echo "10. Testing Large Payloads"
echo "-------------------------------------------"
LARGE_PAYLOAD=$(python3 -c "print('A' * 1000)")
curl -s "$WAF_URL/search?q=$LARGE_PAYLOAD" | head -c 100
echo ""
echo ""

echo "=========================================="
echo "Test Suite Complete!"
echo "=========================================="
echo ""
echo "Check the dashboard at: $WAF_URL/dashboard"
echo "Check metrics at: $WAF_URL/dashboard/metrics"
echo "Check logs at: $WAF_URL/dashboard/logs"
echo "Check bans at: $WAF_URL/dashboard/bans"
echo ""

