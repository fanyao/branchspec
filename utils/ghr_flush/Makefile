CC=gcc-7
CFLAGS=-I.


ghr_flush_test: 
	gcc -O0 ghr_flush_test.c ../../include/*.o -o ghr_flush_test -lpthread -static

all: ghr_flush_test
v1: ghr_flush_test

clean:
	rm ghr_flush_test
