CC=gcc-7
CFLAGS=-I.

.phony: all

all: rm_bin openssl_poc

openssl/libcrypto.a: openssl
	cd openssl && ./Configure no-shared linux-x86_64
	make -C openssl build_libs -j

openssl_poc: openssl/libcrypto.a
	gcc -fno-stack-protector -g -O0 poc.cpp -o openssl_poc -Iopenssl/include -Iopenssl/crypto openssl/libcrypto.a ../../include/randomize_pht.o -DOPENSSL -lrt -ldl -lpthread -lstdc++

rm_bin:
	rm -f openssl_poc

clean:
	make -C openssl clean
	rm openssl_poc