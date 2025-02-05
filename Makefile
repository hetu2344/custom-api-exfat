# COMP 3430 Operating Systems
# Winter 2025
# Franklin Bristow
#
# Students registered in this offering of the course are explicitly permitted
# to copy and use this Makefile for their own work.

CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic -g -D_FORTIFY_SOURCE=3

# make USE_LIBC_INSTEAD=1 
ifdef USE_LIBC_INSTEAD
	CFLAGS := -DUSE_LIBC_INSTEAD $(CFLAGS)
endif

.PHONY: clean

all: cat

ifndef USE_LIBC_INSTEAD
cat: nqp_exfat.o
endif

clean:
	rm -rf cat *.o
