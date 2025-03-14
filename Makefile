
CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic -g -D_FORTIFY_SOURCE=3

# make USE_LIBC_INSTEAD=1 
ifdef USE_LIBC_INSTEAD
	CFLAGS := -DUSE_LIBC_INSTEAD $(CFLAGS)
endif

.PHONY: clean


ifndef USE_LIBC_INSTEAD
all: cat test ls paste

cat: nqp_exfat.o

test: nqp_exfat.o

ls: nqp_exfat.o

paste: nqp_exfat.o
else

all: cat test



endif

clean:
	rm -rf cat ls paste *.o 
