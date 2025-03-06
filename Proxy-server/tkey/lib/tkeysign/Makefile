all:
	go build

.PHONY: lint
lint:
	golangci-lint run

.PHONY: spdx
spdx:
	./tools/spdx-ensure 
