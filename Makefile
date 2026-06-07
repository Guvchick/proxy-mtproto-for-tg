BINARY  := proxy
CMD     := ./cmd/proxy
GENSEC  := ./cmd/gen-secret
LDFLAGS := -ldflags="-s -w" -trimpath

.PHONY: build run gen-secret docker docker-run lint test clean

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/gen-secret $(GENSEC)

run: build
	./bin/$(BINARY) -config config.yaml

gen-secret:
	go run $(GENSEC) -faketls -domain www.google.com -host YOUR_SERVER_IP -port 443

docker:
	docker build -t mtproto-proxy .

docker-run:
	docker-compose up -d

lint:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf bin/
