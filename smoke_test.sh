#!/usr/bin/env bash
set -e
cd /Users/didi/Code/CFP

echo "=== CFP Smoke Test ==="

# Kill any previous test server
pkill -f "cfp server" 2>/dev/null || true
sleep 0.5

# Start server in background, redirect output to file
cargo run -- server \
  --passkey testpass123 \
  --listen 127.0.0.1:18080 \
  --output-dir ./received_test \
  --log-dir ./logs_test \
  > /Users/didi/Code/CFP/server_smoke.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to be ready (RSA keygen can take ~6s in debug mode)
echo "Waiting for server to be ready..."
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ 2>/dev/null | grep -q "200\|400\|405\|422"; then
    echo "Server is up!"
    break
  fi
  sleep 1
  echo "  waiting... ($i)"
done

# Run client
echo "Running client..."
cargo run -- client \
  --file test_input.txt \
  --server http://127.0.0.1:18080 \
  --passkey testpass123 \
  --chunk-min 10 \
  --chunk-max 30 \
  --threads 2 \
  --interval-min-ms 10 \
  --interval-max-ms 50

echo ""
echo "=== Received files ==="
ls -la ./received_test/ 2>/dev/null || echo "(nothing yet)"

echo "=== Server log ==="
cat /Users/didi/Code/CFP/server_smoke.log | tail -30

kill $SERVER_PID 2>/dev/null || true
echo "=== Done ==="
