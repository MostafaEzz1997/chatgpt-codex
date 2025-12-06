CXX ?= g++
CXXFLAGS ?= -std=c++17 -Iinclude -Wall -Wextra -O2

TARGET := rsa_demo
SRCS := src/main.cpp src/rsa.cpp

# Add build directory and platform helpers
BUILD_DIR := build

ifeq ($(OS),Windows_NT)
EXEEXT := .exe
MKDIR = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
RM = del /Q
RMRF = rmdir /S /Q
else
EXEEXT :=
MKDIR = mkdir -p $(BUILD_DIR)
RM = rm -f
RMRF = rm -rf
endif

# Put binary and objects under build/
BIN := $(BUILD_DIR)/rsa_demo$(EXEEXT)

# If SRCS is already defined earlier, map OBJS into BUILD_DIR.
# Example: SRCS := rsa_demo.c foo.c
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

# Compile .c -> build/.o (create build dir first)
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	$(MKDIR)

# Link into build/rsa_demo (executable placed in build/)
$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	-$(RM) $(BIN)
	-$(RMRF) $(BUILD_DIR)
