CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

all: server client

server: SSHServer.cpp DiffieHellman.hpp CryptoManager.hpp Protocol.hpp
	$(CXX) $(CXXFLAGS) -o server SSHServer.cpp $(LDFLAGS)

client: SSHClient.cpp DiffieHellman.hpp CryptoManager.hpp Protocol.hpp
	$(CXX) $(CXXFLAGS) -o client SSHClient.cpp $(LDFLAGS)

clean:
	rm -f server client