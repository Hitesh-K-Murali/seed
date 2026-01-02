CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -lselinux

SRC_DIR = src
KERNEL_DIR = kernel
BUILD_DIR = build

# List source files
SRC_SOURCES = $(wildcard $(SRC_DIR)/*.c)
KERNEL_SOURCES = $(wildcard $(KERNEL_DIR)/*.c)

# List object files
SRC_OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/src/%.o, $(SRC_SOURCES))
KERNEL_OBJECTS = $(patsubst $(KERNEL_DIR)/%.c, $(BUILD_DIR)/kernel/%.o, $(KERNEL_SOURCES))

# Main target
all: $(BUILD_DIR)/main $(BUILD_DIR)/kernel_image

# Link main executable
$(BUILD_DIR)/main: $(SRC_OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Link kernel image (dummy target for now)
$(BUILD_DIR)/kernel_image: $(KERNEL_OBJECTS)
	@mkdir -p $(@D)
	# This is a placeholder for actual kernel linking
	ld -r $^ -o $@

# Compile src files
$(BUILD_DIR)/src/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile kernel files
$(BUILD_DIR)/kernel/%.o: $(KERNEL_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -ffreestanding -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
