BINARY      := $(notdir $(CURDIR))
FRIDA_DEVKIT := $(CURDIR)/build/frida-devkit
FRIDA_VERSION ?= `frida --version`

CGO_CFLAGS  := -I$(FRIDA_DEVKIT)
CGO_LDFLAGS := -L$(FRIDA_DEVKIT)

export CGO_CFLAGS
export CGO_LDFLAGS

.PHONY: all build test clean devkit generate-ts

all: build

devkit:
	@bash scripts/get-devkit.sh $(FRIDA_VERSION)

# Recompile dump.ts → internal/assets/dump.js and commit the result.
# Run this whenever assets/dump.ts changes.
generate-ts: $(FRIDA_DEVKIT)/frida-core.h
	go generate .

build: $(FRIDA_DEVKIT)/frida-core.h
	go build -o $(BINARY) .

test: $(FRIDA_DEVKIT)/frida-core.h
	go test ./...

clean:
	rm -f $(BINARY)

$(FRIDA_DEVKIT)/frida-core.h:
	@echo "frida-devkit not found. Run: make devkit [FRIDA_VERSION=x.y.z]"
	@exit 1
