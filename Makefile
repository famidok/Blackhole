# Makefile

CLANG=clang
GCC=gcc

CLANG_FLAGS=-O2 -g -Wall -target bpf

BUILD_DIR=build

.PHONY: all clean

all: $(BUILD_DIR)/blacklist.o $(BUILD_DIR)/blacklist_config_writer $(BUILD_DIR)/blacklist_map copy_script

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/blacklist.o: src/core/blacklist.c | $(BUILD_DIR)
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(BUILD_DIR)/blacklist_config_writer: src/helpers/blacklist_config_writer.c | $(BUILD_DIR)
	$(GCC) -o $@ $<

$(BUILD_DIR)/blacklist_map: src/maps/blacklist_map.c | $(BUILD_DIR)
	$(GCC) -o $@ $< -lbpf -ljansson -lpthread

copy_script:
	cp src/scripts/Run.sh ./Run.sh
	cp src/scripts/Unload.sh ./Unload.sh
	chmod +x ./Run.sh
	chmod +x ./Unload.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -rf Run.sh
	rm -rf Unload.sh
