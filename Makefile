NAME=manifesto
PACKAGE_NAME=github.com/aquasecurity/$(NAME)
TAG=$$(git describe --abbrev=0 --tags)

LDFLAGS += -X "$(PACKAGE_NAME)/version.BuildTime=$(shell date -u '+%Y-%m-%d %I:%M:%S %Z')"
LDFLAGS += -X "$(PACKAGE_NAME)/version.BuildVersion=$(shell git describe --abbrev=0 --tags)"
LDFLAGS += -X "$(PACKAGE_NAME)/version.BuildSHA=$(shell git rev-parse HEAD)"
# Strip debug information
LDFLAGS += -s

ifeq ($(OS),Windows_NT)
	suffix := .exe
endif

all: build test

$(GOPATH)/bin/glide$(suffix):
	go get github.com/Masterminds/glide

$(GOPATH)/bin/manifesto$(suffix):
	go get github.com/aquasecurity/manifesto

glide.lock: glide.yaml $(GOPATH)/bin/glide$(suffix)
	glide update
	@touch $@

vendor: glide.lock
	glide install
	@touch $@

releases:
	mkdir -p releases

bin/linux/amd64:
	mkdir -p bin/linux/amd64

bin/windows/amd64:
	mkdir -p bin/windows/amd64

bin/darwin/amd64:
	mkdir -p bin/darwin/amd64

build: darwin linux windows

test:
	go test -v $(shell go list ./... | grep -v /vendor/)

darwin: vendor releases bin/darwin/amd64
	env GOOS=darwin GOAARCH=amd64 go build -ldflags '$(LDFLAGS)' -v -o $(CURDIR)/bin/darwin/amd64/$(NAME)
	tar -cvzf releases/$(NAME)-darwin-amd64.tar.gz bin/darwin/amd64/$(NAME)

linux: vendor releases bin/linux/amd64
	env GOOS=linux GOAARCH=amd64 go build -ldflags '$(LDFLAGS)' -v -o $(CURDIR)/bin/linux/amd64/$(NAME)
	tar -cvzf releases/$(NAME)-linux-amd64.tar.gz bin/linux/amd64/$(NAME)

windows: vendor releases bin/windows/amd64
	env GOOS=windows GOAARCH=amd64 go build -ldflags '$(LDFLAGS)' -v -o $(CURDIR)/bin/windows/amd64/$(NAME).exe
	tar -cvzf releases/$(NAME)-windows-amd64.tar.gz bin/windows/amd64/$(NAME).exe

clean:
	rm -fr releases bin

