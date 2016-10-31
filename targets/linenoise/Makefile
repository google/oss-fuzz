PROJ=$(notdir $(shell pwd))

CFLAGS:=-Wall -Werror -ggdb

.PHONY: all
all: lib$(PROJ).a

.PHONY: clean
clean:
	rm -f *.a *.o

lib$(PROJ).a : wrapper.o
	ar rcs $@ $^

%.o : %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<
