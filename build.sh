#!/bin/sh
# Mac / Linux build:  sh build.sh
set -e
g++ -std=c++14 -O2 -Wall -Wextra src/server.cpp src/coding.cpp -o server
g++ -std=c++14 -O2 -Wall -Wextra src/client.cpp src/coding.cpp -o client
g++ -std=c++14 -O2 -Wall -Wextra src/test_packet.cpp -o test_packet
g++ -std=c++14 -O2 -Wall -Wextra src/test_coding.cpp src/coding.cpp -o test_coding
echo "built: server client test_packet test_coding"
 