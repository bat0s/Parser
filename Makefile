CC  :=   gcc
CFLAGS  =   -Wall -Wextra -Wpedantic -Ofast
LDFLAGS  =   -lcurl

all:
	$(CC) $(CFLAGS) $(LDFLAGS) parser.c -o parser

clean:
	rm -rf parser