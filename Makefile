CC      := gcc
CFLAGS := -Wall -std=c23 -g

TARGET  := aescbc
SRC := \
	aescbc.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean rebuild

all: $(TARGET)

$(TARGET): $(OBJ)
	@$(CC) $(OBJ) -o aescbc
	@rm -f $(OBJ)

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -f $(OBJ) $(TARGET)

rebuild: clean all
