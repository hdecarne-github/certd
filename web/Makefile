NPM := $(shell command -v npm 2> /dev/null)

.DEFAULT_GOAL := build

.PHONY: deps
deps:
	$(NPM) install

.PHONY: build
build: deps
	$(NPM) run build
	
.PHONY: test
test: test
	$(NPM) run test
