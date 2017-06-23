
callCPP: callCPPFromJava.cpp lib/ope.o lib/hgd.o
	g++ -fPIC -Wl,--whole-archive lib/ope.o -Wl,--whole-archive lib/hgd.o -Wl,--no-whole-archive -shared -I"/usr/java/jdk1.7.0_25/include" -I"/usr/java/jdk1.7.0_25/include/linux" -std=c++0x -lntl -lgmp -lcrypto -o libope.so callCPPFromJava.cpp

example: example.cpp lib/ope.a
	g++ example.cpp lib/ope.a -std=c++0x  -lntl -lgmp  -lcrypto -o example

encrypt_utils: lib/ope.a
	g++ decrypt.cpp lib/ope.a -std=c++0x  -lntl -lgmp  -lcrypto -o decrypt
	g++ encrypt.cpp lib/ope.a -std=c++0x  -lntl -lgmp  -lcrypto -o encrypt
	g++ encryptrange.cpp lib/ope.a -std=c++0x  -lntl -lgmp  -lcrypto -o encryptrange
	g++ encryptrangeshuffle.cpp lib/ope.a -std=c++0x  -lntl -lgmp  -lcrypto -o encryptrangeshuffle

	
JavaHeaders: callCPPFromJava.java
	javac callCPPFromJava.java
	javah callCPPFromJava

lib/ope.o:
	make -C lib/

lib/ope.a:
	make lib_ope_cryptdb_2 -C lib/

lib/hgd.o:
	make -C lib/

clean:
	make clean -C lib/
	rm -f libope.so
	rm -f example
	rm -f encrypt
	rm -f decrypt
	rm -f callCPPFromJava.class
