.PHONY: build clean test screenshots

build:
	go build -o bin/gateway-proxy ./cmd/gateway-proxy
	go build -o bin/gateway-torpool ./cmd/gateway-torpool

clean:
	rm -rf bin/

test:
	go test ./... -v -race -count=1

screenshots:
	PATH="/c/msys64/mingw64/bin:$$PATH" go run ./tests/screenshots -out=docs/screenshots
