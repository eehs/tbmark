CC=gcc
CFLAGS=-O2 -fdata-sections -ffunction-sections -g -Wall -fstack-protector-strong -Wno-error
CLIBS=-lxdo
SRC_DIR=src
IPROGRAMS_DIR=$(SRC_DIR)/iprograms
OBJ_DIR=obj
BIN_FILE=tbmark
SRC_FILES=$(wildcard $(SRC_DIR)/*.c)
PROGRAM_FILES=$(wildcard $(IPROGRAMS_DIR)/*.c)
OBJ_FILES=$(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))
PROGRAM_OBJ_FILES=$(patsubst $(IPROGRAMS_DIR)/%.c, $(OBJ_DIR)/%.o, $(PROGRAM_FILES))

all: $(OBJ_DIR) $(BIN_FILE)

$(OBJ_DIR):
	mkdir $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $^ -o $@

$(OBJ_DIR)/%.o: $(IPROGRAMS_DIR)/%.c
	$(CC) $(CFLAGS) -c $^ -o $@

$(BIN_FILE): $(OBJ_FILES) $(PROGRAM_OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@ $(CLIBS) -Wl,--gc-sections

clean:
	rm -rf $(BIN_FILE) $(OBJ_DIR)
