CC=gcc

MHASH=${HOME}/mhash
MHASH_INCLUDE=${MHASH}/include
MHASH_LIB=${MHASH}/lib
MHASH_ARCHIVE=${MHASH_LIB}/libmhash.a

CFLAGS=-I$(MHASH_INCLUDE) -Wall -g -static

OBJ=fsc.o 
INCLUDES=types.h

fsc: $(OBJ) $(INCLUDES)
	$(CC) $(CFLAGS) $(OBJ) $(MHASH_ARCHIVE) -o fsc

fsc.o: fsc.c $(INCLUDES)
	$(CC) $(CFLAGS) -c fsc.c

clean:
	rm -f *.o

