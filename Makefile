CC = gcc
LD = gcc
CFLAGS = -Wall -Winline -O4
LDFLAGS =

OBJS = crapto1.o crypto1.o
HEADERS = 
EXES = mf_nonce_brute
LIBS = 
	
all: $(OBJS) $(EXES) $(LIBS)

% : %.c $(OBJS)
	$(LD) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS) -lpthread

clean: 
	rm -f $(OBJS) $(EXES) $(LIBS) 
