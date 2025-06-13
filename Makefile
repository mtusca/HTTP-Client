CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -pedantic -O2

SRC     = client.c helpers.c buffer.c requests.c parson.c
OBJ     = $(SRC:.c=.o)
BIN     = client

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(BIN)
	chmod +x $(BIN)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
