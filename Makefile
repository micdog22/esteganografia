# Makefile do Esteganografia.
# Variáveis que podem ser trocadas: CC, CFLAGS, LDFLAGS, BUILD.
#   make             compila build/esteg
#   make test        testes de unidade e da linha de comando
#   make sanitize    os mesmos testes com AddressSanitizer e UBSan
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS = -lm
BUILD ?= build
ALL_CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Iinclude -Isrc -Itests $(CFLAGS)
HEADERS = include/esteg.h src/cripto.h tests/bmp_sintetico.h

LIB_SRC = src/aleatorio.c src/analise.c src/bmp.c src/chacha20.c src/esteg.c src/sha256.c
LIB_OBJ = $(LIB_SRC:src/%.c=$(BUILD)/%.o)

all: $(BUILD)/esteg

$(BUILD)/%.o: src/%.c $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD)/libesteg.a: $(LIB_OBJ)
	$(AR) rcs $@ $(LIB_OBJ)

$(BUILD)/esteg: $(BUILD)/main.o $(BUILD)/libesteg.a
	$(CC) $(CFLAGS) $(BUILD)/main.o $(BUILD)/libesteg.a $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/test_esteg: tests/test_esteg.c tests/teste.h tests/bmp_sintetico.c $(BUILD)/libesteg.a $(HEADERS)
	$(CC) $(ALL_CFLAGS) tests/test_esteg.c tests/bmp_sintetico.c $(BUILD)/libesteg.a $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/gerar_bmp: tests/gerar_bmp.c tests/bmp_sintetico.c tests/bmp_sintetico.h
	@mkdir -p $(BUILD)
	$(CC) $(ALL_CFLAGS) tests/gerar_bmp.c tests/bmp_sintetico.c $(LDFLAGS) $(LDLIBS) -o $@

test: $(BUILD)/test_esteg $(BUILD)/esteg $(BUILD)/gerar_bmp
	./$(BUILD)/test_esteg
	sh tests/cli.sh ./$(BUILD)/esteg ./$(BUILD)/gerar_bmp

sanitize:
	$(MAKE) BUILD=$(BUILD)/sanitize CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" test

clean:
	rm -rf $(BUILD)

.PHONY: all test sanitize clean
