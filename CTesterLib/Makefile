LIB = libctester.a
CC = cc
AR = ar
CFLAGS = -c -Wall

CTester.o : CTester.c
	$(CC) $(CFLAGS)  $^ -o $@

libctester.a : CTester.o
	$(AR) rcs  $@ $^

.PHONY: all
all : $(LIB)