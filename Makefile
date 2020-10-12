SHELL             := bash
.SHELLFLAGS       := -eu -o pipefail -c
.DEFAULT_GOAL     := default
.DELETE_ON_ERROR  :
.SUFFIXES         :# Go parameters

GOCMD	:= go
GOBUILD := $(GOCMD) build
GOTEST 	:= $(GOCMD)	test

.PHONY: test-unit
test-unit:
	$(GOTEST) ./...

.PHONY: test-integration
test-integration:
	docker-compose up -d; \
	sleep 10; \
	$(GOTEST) -v -tags=integration -run=Integration ./...; \
	docker-compose down