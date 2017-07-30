# Package information
CLI 			?= main.go

PACKAGE		?= kx-ipmd5-brute
PACKAGES	:= $(shell go list ./...)
VERSION		?= $(shell git describe --match '[0-9]*\.[0-9]*\.[0-9]*' --tags --abbrev=0 &> /dev/null || echo "0.1")
COMMIT		?= $(shell git log --pretty=format:'%h' -n 1 || echo "unknown")

# Flags
VERSION_FLAGS	:= "-X github.com/jlettman/kx-ipmd5-brute/brute.Version=${VERSION} -X github.com/jlettman/kx-ipmd5-brute/brute.Commit=${COMMIT}"

# Binary
BIN 		?= $(PACKAGE)

# Tools
GO		?= go

###############
# Build tasks #
###############

default: build
.PHONY: default

build: $(BIN)

$(BIN): clean
	$(GO) build -ldflags $(VERSION_FLAGS) -o $(BIN) .

build-clean:
	rm -f $(BIN)

#############
# Run tasks #
#############

run:
	$(GO) run -ldflags $(VERSION_FLAGS) $(CLI)

####################
# Dependency tasks #
####################

depends:
	$(GO) get $(PACKAGES)

###############
# Clean tasks #
###############

clean: build-clean
