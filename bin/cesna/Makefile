# Compiler and flags
CC = gcc
CFLAGS = -g -O0

# Find all .c files in current directory
SOURCES = $(wildcard *.c)
# Create executable names by removing .c extension
TARGETS = $(SOURCES:.c=)

# Default target - build all executables
all: $(TARGETS)

# Pattern rule to build each executable from its .c file
%: %.c messages.h
	$(CC) $(CFLAGS) $< -o $@

# Clean target to remove all executables
clean:
	rm -f $(TARGETS)

# Phony targets
.PHONY: all clean