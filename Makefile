.PHONY: all clean

CFLAGS=-O9
OBJS=sha3.o

all: pow

pow: pow.c $(OBJS)
	$(CC) $(CFLAGS) -lcrypto -lm -lpthread $^ -o $@

clean:
	rm -f pow $(OBJS)
