#!/bin/sh -e

TARGET_IP="127.0.0.1"
TARGET_PORT="8080"

# long-term connection
/bin/nc $TARGET_IP $TARGET_PORT &

while true; do
    curl http://$TARGET_IP:$TARGET_PORT &> /dev/null
done
