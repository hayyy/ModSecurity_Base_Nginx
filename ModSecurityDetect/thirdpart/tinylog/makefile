BIN=libtlog.so

CFLAGS +=-O2 -fPIC -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough

$(BIN): tlog.o
	$(CC) -shared -o $@ $^

install:
	cp $(BIN) /usr/local/lib/
	cp tlog.h /usr/local/include/

clean:
	$(RM) *.o $(BIN)