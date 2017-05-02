.PHONY: all clean

all: pow

pow: pow.c
	gcc -O9 -lcrypto -lm -lpthread $< -o $@

clean:
	rm -f pow
