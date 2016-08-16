CC = gcc
LD = gcc
CFLAGS = -std=c99 -Wall -Winline -O3
LDFLAGS =

OBJS = crapto1.o crypto1.o iso14443crc.o
HEADERS = crapto1.h iso14443crc.h
EXES = mf_nonce_brute
LIBS = 
	
all: $(OBJS) $(EXES) $(LIBS)

% : %.c $(OBJS)
	$(LD) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS) -lpthread

clean: 
	rm -f $(OBJS) $(EXES) $(LIBS) 
