#!/bin/bash

killall -9 server target_app client 2>/dev/null
rm server target_app client 2>/dev/null

g++ TargetApp.cpp -o target_app
g++ SSHServer.cpp -o server -pthread -lssl -lcrypto
g++ SSHClient.cpp -o client -lssl -lcrypto

./target_app > target_log.txt &
TARGET_PID=$!

./server > server_log.txt &
SERVER_PID=$!
sleep 1

echo "--- MULTICLIENT IMAGE TRANSFER TEST ---"

./client artifacts/first_image.jpeg &
PID1=$!
echo "[TEST] Client 1 (Image 1) started with PID $PID1..."

./client artifacts/second_image.jpeg &
PID2=$!
echo "[TEST] Client 2 (Image 2) started with PID $PID2..."

./client artifacts/third_image.jpeg &
PID3=$!
echo "[TEST] Client 3 (Image 3) started with PID $PID3..."

wait $PID1 $PID2 $PID3

echo "--- TRANSFERS ARE COMPLETED ---"

kill $TARGET_PID $SERVER_PID