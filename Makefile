.PHONY: build clean test

build:
	go build -o bin/gateway-proxy ./cmd/gateway-proxy
	go build -o bin/gateway-torpool ./cmd/gateway-torpool

clean:
	rm -rf bin/

test:
	go test ./... -v -race -count=1
