# TerraGuard developer commands. Requires Go (see go.mod); Python 3 for evals.
BIN := bin/terraguard

.PHONY: all build test web serve evals worker-test secrets clean

all: test build web

build: web            ## CLI + MCP + self-hosted server (embeds the web app)
	go build -o $(BIN) ./cmd/terraguard

test:                 ## unit tests
	go vet ./...
	go test -race ./...

web:                  ## WebAssembly site into web/
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/terraguard.wasm ./cmd/wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
	rm -rf web/examples && cp -r examples web/examples

serve: build          ## self-hosted app on http://127.0.0.1:8080 (reads .env)
	$(BIN) serve

evals: build          ## rule precision/recall regression gate
	python3 evals/run_evals.py --binary $(BIN)

worker-test:          ## Cloudflare stats worker unit tests
	cd stats-worker && npm test

secrets:              ## fail if any credential is tracked by git
	scripts/check-secrets.sh --all

clean:
	rm -rf bin web/terraguard.wasm web/wasm_exec.js web/examples
