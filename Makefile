CXX ?= g++
CXXFLAGS ?= -std=c++17 -Iinclude -Wall -Wextra -O2

TARGET := rsa_demo
SRCS := src/main.cpp src/rsa.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
