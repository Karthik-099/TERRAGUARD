# TerraGuard developer commands. Requires only Go (see go.mod).
BIN := bin/terraguard

.PHONY: all build test web vendor serve evals policy-test worker-test secrets clean

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

vendor:               ## copy browser libraries into web/vendor for air-gapped installs
	rm -rf web/vendor && mkdir -p web/vendor
	curl -fsSL https://registry.npmjs.org/monaco-editor/-/monaco-editor-0.52.2.tgz | tar -xz -C web/vendor package/min/vs
	mv web/vendor/package web/vendor/monaco
	curl -fsSL -o web/vendor/cytoscape.min.js https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js
	curl -fsSL -o web/vendor/marked.min.js https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js
	curl -fsSL -o web/vendor/purify.min.js https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js

serve: build          ## self-hosted app on http://127.0.0.1:8080 (reads .env)
	$(BIN) serve

evals: build          ## rule regression gate: every labelled case must fire or stay quiet as expected
	$(BIN) policy test evals/cases

policy-test: build    ## run the example policy pack's fixtures
	$(BIN) policy test examples/policies/tests --config examples/policies/team-payments.yml

worker-test:          ## Cloudflare stats worker unit tests
	cd stats-worker && npm test

secrets:              ## fail if any credential is tracked by git
	scripts/check-secrets.sh --all

clean:
	rm -rf bin web/terraguard.wasm web/wasm_exec.js web/examples web/vendor
