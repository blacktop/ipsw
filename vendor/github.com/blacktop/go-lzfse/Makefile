MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENT_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))

TARGET := lzfse.go

all : $(TARGET)

build:
	go build -v -x .

install:
	go install -v -x .

vendor/lzfse:
	git submodule update --init
	cd $(CURRENT_DIR)/vendor/lzfse && \
	xcodebuild install DSTROOT=$(CURRENT_DIR) && \
	mv $(CURRENT_DIR)/include/lzfse.h $(CURRENT_DIR) && \
	${RM} -r $(CURRENT_DIR)/bin $(CURRENT_DIR)/include && \
	chmod 644 $(CURRENT_DIR)/lzfse.h

$(TARGET): lzfse.yml vendor/lzfse
	@c-for-go lzfse.yml
	@mv -f lzfse/* .
	@${RM} -r lzfse

clean:
	${RM} -r lib vendor/lzfse

.PHONY: build install clean