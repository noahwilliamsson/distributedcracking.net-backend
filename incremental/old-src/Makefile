CC=gcc
CFLAGS=-Wall -O2 -funroll-loops -ggdb
generatepacket: generate.o charset.o
	$(CC) -o generatepacket generate.o charset.o $(CFLAGS)

clean:
	rm -f *.o generatepacket
