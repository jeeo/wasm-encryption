build:
	GOOS=js GOARCH=wasm go build -o assets/main.wasm cmd/wasm/main.go
run:
	go run cmd/server/main.go