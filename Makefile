LZMA_LIBDIR := $(shell pkg-config --variable=libdir liblzma)

CFLAGS   ?= -std=c17 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS += $(shell pkg-config --cflags liblzma) -DLZMA_API_STATIC
LDLIBS   += $(LZMA_LIBDIR)/liblzma.a $(filter-out -llzma,$(shell pkg-config --static --libs liblzma))

SRC_DIR   := src
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/packguard

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
