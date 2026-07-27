BIN=caddy-analyze

build:
	go build -o $(BIN) ./cmd/caddy-analyze/

run: build
	./$(BIN) $(ARGS)

install:
	go install ./cmd/caddy-analyze/

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BIN)

.PHONY: build run install test lint clean
