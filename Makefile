all: clean makedir Crypto TreeNode Query Server Client
	cc -g src/build/Crypto.o src/build/TreeNode.o src/build/Query.o src/build/Server.o -o src/build/Server -lcrypto
	cc -g src/build/Crypto.o src/build/TreeNode.o src/build/Query.o src/build/Client.o -o src/build/Client -lcrypto

local: clean makedir Crypto TreeNode Query LocalTest
	cc -g src/build/Crypto.o src/build/TreeNode.o src/build/Query.o src/build/localTest.o -o src/build/localTest -lcrypto

Crypto:
	cc -g -c src/Crypto.c -o src/build/Crypto.o

TreeNode:
	cc -g -c src/TreeNode.c -o src/build/TreeNode.o

Query:
	cc -g -c src/Query.c -o src/build/Query.o

LocalTest:
	cc -g -c src/localTest.c -o src/build/localTest.o

Server:
	cc -g -c src/Server.c -o src/build/Server.o

Client:
	cc -g -c src/Client.c -o src/build/Client.o

makedir:
	mkdir src/build

clean:
	rm -rf src/build