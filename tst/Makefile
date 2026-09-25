CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -std=c11
LDFLAGS  :=

TARGET   := test_drv
SRC      := test_drv.c
OBJ      := $(SRC:.c=.o)

DEVICE   := /dev/crypt_drv

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: $(TARGET)
	@if [ ! -c $(DEVICE) ]; then \
		echo "✗ Устройство $(DEVICE) не найдено. "; \
		exit 1; \
	fi

	@./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJ)
