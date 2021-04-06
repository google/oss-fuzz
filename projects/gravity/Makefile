COMPILER_DIR = src/compiler/
RUNTIME_DIR = src/runtime/
SHARED_DIR = src/shared/
UTILS_DIR = src/utils/
OPT_DIR = src/optionals/
GRAVITY_SRC = src/cli/gravity.c
EXAMPLE_SRC = examples/example.c

#CC ?= gcc

SRC = $(wildcard $(COMPILER_DIR)*.c) \
      $(wildcard $(RUNTIME_DIR)*.c) \
      $(wildcard $(SHARED_DIR)*.c) \
      $(wildcard $(UTILS_DIR)*.c) \
      $(wildcard $(OPT_DIR)*.c)

INCLUDE = -I$(COMPILER_DIR) -I$(RUNTIME_DIR) -I$(SHARED_DIR) -I$(UTILS_DIR) -I$(OPT_DIR)
CFLAGS += $(INCLUDE) -std=gnu99 -fgnu89-inline -fPIC -DBUILD_GRAVITY_API
OBJ = $(SRC:.c=.o)

ifeq ($(OS),Windows_NT)
	# Windows
	LIBTARGET = gravity.dll
	LDFLAGS = -lm -lShlwapi
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		# MacOS
		LIBTARGET = libgravity.dylib
		LDFLAGS = -lm
	else ifeq ($(UNAME_S),OpenBSD)
		# OpenBSD
		CFLAGS += -D_WITH_GETLINE
		LDFLAGS = -lm
	else ifeq ($(UNAME_S),FreeBSD)
		# FreeBSD
		CFLAGS += -D_WITH_GETLINE
		LDFLAGS = -lm
	else ifeq ($(UNAME_S),NetBSD)
		# NetBSD
		CFLAGS += -D_WITH_GETLINE
		LDFLAGS = -lm
	else ifeq ($(UNAME_S),DragonFly)
		# DragonFly
		CFLAGS += -D_WITH_GETLINE
		LDFLAGS = -lm
	else
		# Linux
		LIBTARGET = libgravity.so
		LDFLAGS = -lm -lrt
	endif
endif

ifeq ($(mode),debug)
	CFLAGS += -g -O0 -DDEBUG
else
	CFLAGS += -O2
endif


all: gravity

gravity:	$(OBJ) $(GRAVITY_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	
example:	$(OBJ) $(EXAMPLE_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

lib: gravity
	$(CC) -shared -o $(LIBTARGET) $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) gravity example libgravity.so gravity.dll
	
.PHONY: all clean gravity example
