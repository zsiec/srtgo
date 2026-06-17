.PHONY: test lint bench build examples sansio-check

test:
	go test -race -count=1 -timeout 120s ./...

# Verify the Sans-I/O protocol core stays free of direct net/time imports.
sansio-check:
	./scripts/check-sansio.sh

lint:
	go vet ./...

bench:
	go test -bench=. -benchmem ./...

build:
	go build ./...

examples:
	go build ./examples/...
