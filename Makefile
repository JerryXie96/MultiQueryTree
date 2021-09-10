all: clean makedir Crypto TreeNode Query LocalTest
	cc src/build/Crypto.o src/build/TreeNode.o src/build/Query.o src/build/localTest.o -o localTest -lcrypto

Crypto:
	cc -c src/Crypto.c -o src/build/Crypto.o

TreeNode:
	cc -c src/TreeNode.c -o src/build/TreeNode.o

Query:
	cc -c src/Query.c -o src/build/Query.o

LocalTest:
	cc -c src/localTest.c -o src/build/localTest.o

makedir:
	mkdir src/build

clean:
	rm -rf src/build