CC=gcc-7
CFLAGS=-I.


poc_v1: 
	gcc-7 -O0 poc_v1.c include/*.o -o poc_v1 -lpthread -static
poc_v2: 
	gcc -O0 poc_v2.c include/*.o -o poc_v2 -lpthread -static

all: poc_v1 poc_v2
v1: poc_v1
v2: poc_v2

clean:
	rm poc_v1 poc_v2
