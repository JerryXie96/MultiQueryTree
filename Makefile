all: clean makedir Crypto TreeNode Query Server Client KeyGenerator
	cc -O2 ./build/Crypto.o ./build/TreeNode.o ./build/Query.o ./build/Server.o -o ./build/Server -lcrypto
	cc -O2 ./build/Crypto.o ./build/TreeNode.o ./build/Query.o ./build/Client.o -o ./build/Client -lcrypto

local: clean makedir Crypto TreeNode Query LocalTest KeyGenerator
	cc -O2 ./build/Crypto.o ./build/TreeNode.o ./build/Query.o ./build/localTest.o -o ./build/localTest -lcrypto

Crypto:
	cc -O2 -c src/Crypto.c -o ./build/Crypto.o

TreeNode:
	cc -O2 -c src/TreeNode.c -o ./build/TreeNode.o

Query:
	cc -O2 -c src/Query.c -o ./build/Query.o

LocalTest:
	cc -O2 -c src/localTest.c -o ./build/localTest.o

Server:
	cc -O2 -c src/Server.c -o ./build/Server.o

Client:
	cc -O2 -c src/Client.c -o ./build/Client.o

KeyGenerator:
	cc -O2 src/KeyGenerator.c -o ./build/KeyGenerator -lcrypto

makedir:
	mkdir ./build

clean:
	rm -rf ./build