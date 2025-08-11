#!/bin/bash
set -e

# Build binaries
cargo build --release

# Start rate limiter in background
./target/release/actix_ratelimiter &
RL_PID=$!

# Wait a bit to ensure it starts
sleep 1

# Start server in background
./target/release/actix_server &
SRV_PID=$!

# Wait a bit to ensure it starts
sleep 1


# 1) Enroll
ENROLL_RESPONSE=$(curl -s -X POST http://127.0.0.1:8080/enroll \
  -H "Content-Type: application/json" \
  -d '{"password":"securepassword"}')

echo "Enroll Response: $ENROLL_RESPONSE"

# Option A: keep quotes around .record (DO NOT use -r here)
RECORD_JSON=$(echo "$ENROLL_RESPONSE" | jq '.record')

# 2) Decrypt (send record as a JSON string)
DECRYPT_RESPONSE=$(curl -s -X POST http://127.0.0.1:8080/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"record\": ${RECORD_JSON}, \"password\": \"securepassword\"}")

echo "Decrypt Response: $DECRYPT_RESPONSE"

# Kill background processes
kill $SRV_PID $RL_PID
