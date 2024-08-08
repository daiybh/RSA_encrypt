RSADemo: RSADemo.o
	g++ -g -pipe -Wall -o RSADemo RSADemo.o -L../openssl_static/linux64 -ldl -lcrypto -lOpensource -MMD
RSADemo.o: RSADemo.cpp
	g++ -g -pipe -Wall -c RSADemo.cpp -I../openssl_static -MMD
clean:
	rm -f RSADemo.o RSADemo
