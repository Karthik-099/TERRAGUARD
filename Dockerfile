# TerraGuard self-hosted: web app + API + CLI in one ~20 MB distroless image.
#   docker build -t terraguard .
#   docker run --rm -p 127.0.0.1:8080:8080 --env-file .env terraguard
#   docker run --rm -v "$PWD:/src" -w /src terraguard scan .
FROM golang:1.25-alpine AS build
RUN apk add --no-cache make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# web/ must be built first so terraguard.wasm is embedded into the binary.
RUN make web && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/terraguard ./cmd/terraguard

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/terraguard /usr/local/bin/terraguard
USER nonroot
EXPOSE 8080
ENTRYPOINT ["terraguard"]
CMD ["serve", "--addr", "0.0.0.0:8080"]
