#!/usr/bin/make -f

SHELL := /bin/sh
.SHELLFLAGS := -euc

DESTDIR ?=

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

GIT := git
GO := go
GOFMT := gofmt
GOSEC := gosec
GOVULNCHECK := govulncheck
STATICCHECK := staticcheck
INSTALL := install

INSTALL_PROGRAM := $(INSTALL)
INSTALL_DATA := $(INSTALL) -m 644

GIT_TAG := $(shell '$(GIT)' tag -l --contains HEAD)
GIT_SHA := $(shell '$(GIT)' rev-parse HEAD | cut -c1-8)
VERSION := $(if $(GIT_TAG),$(GIT_TAG),$(GIT_SHA))

GOOS := $(shell '$(GO)' env GOOS)
GOARCH := $(shell '$(GO)' env GOARCH)
GOVARIANT := $(GO386)$(GOAMD64)$(GOARM)$(GOMIPS)$(GOMIPS64)$(GOPPC64)
export CGO_ENABLED ?= 0

GOFLAGS := -trimpath
LDFLAGS := -s -w -X "github.com/hectorm/cardea/internal/config.Version=$(VERSION)"

SRCS := $(shell '$(GIT)' ls-files '*.go' 2>/dev/null ||:)
EXEC := cardea-$(VERSION)-$(GOOS)-$(GOARCH)

ifneq ($(GOVARIANT),)
	EXEC := $(addsuffix -$(GOVARIANT), $(EXEC))
endif

ifeq ($(GOOS),windows)
	EXEC := $(addsuffix .exe, $(EXEC))
endif

.PHONY: all
all: test build

.PHONY: build
build: ./dist/$(EXEC)

.PHONY: run
run: ./dist/$(EXEC)
	'$<'

./dist/$(EXEC): $(SRCS)
	@mkdir -p "$$(dirname '$@')"
	'$(GO)' build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o '$@' ./cmd/cardea/

.PHONY: gofmt
gofmt:
	@test -z "$$('$(GOFMT)' -s -l ./ | tee /dev/stderr)"

.PHONY: gosec
gosec:
	'$(GOSEC)' -tests ./...

.PHONY: govulncheck
govulncheck:
	'$(GOVULNCHECK)' -test ./...

.PHONY: staticcheck
staticcheck:
	'$(STATICCHECK)' -tests ./...

.PHONY: test
test:
	'$(GO)' test -v -count=1 -timeout=120s ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 '$(GO)' test -v -count=1 -timeout=240s -race ./...

.PHONY: install
install:
	@mkdir -p '$(DESTDIR)$(bindir)'
	$(INSTALL_PROGRAM) './dist/$(EXEC)' '$(DESTDIR)$(bindir)/cardea'

PHONY: installcheck
installcheck:
	@test -x '$(DESTDIR)$(bindir)/cardea'

.PHONY: uninstall
uninstall:
	rm -fv '$(DESTDIR)$(bindir)/cardea'

.PHONY: clean
clean:
	rm -rfv './dist/'
