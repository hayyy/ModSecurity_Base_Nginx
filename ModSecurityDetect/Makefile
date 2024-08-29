CC = gcc


CFLAGS = -Wall -g -I./thirdpart -I/usr/local/modsecurity/include/ -L/usr/local/modsecurity/lib 

LDLIBS = -ltlog -lhttp_parser -liniparser -lpthread -lmodsecurity -ljemalloc

SRC = $(wildcard *.c)

OBJ = $(SRC:.c=.o)

TARGET = firewall_detect

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJ) $(TARGET)
