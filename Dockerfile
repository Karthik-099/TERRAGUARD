# TerraGuard: CLI, web app and API in one small distroless image (non-root).
#   docker build -t terraguard .
#   docker run --rm -p 127.0.0.1:8080:8080 --env-file .env terraguard
#   docker run --rm -v "$PWD:/src" -w /src terraguard scan .
FROM golang:1.26.10-alpine AS build
RUN apk add --no-cache make curl
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# web/ is built first so terraguard.wasm and the vendored libraries are
# embedded: the image serves everything itself and works without internet.
RUN make web vendor && sed -i 's|assetsBase: ""|assetsBase: "vendor"|' web/config.js && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/terraguard ./cmd/terraguard

# debug-nonroot adds a ~1 MB busybox shell so GitLab CI and Jenkins can run script steps.
FROM gcr.io/distroless/static-debian12:debug-nonroot
COPY --from=build /out/terraguard /usr/local/bin/terraguard
USER nonroot
EXPOSE 8080
ENTRYPOINT ["terraguard"]
CMD ["serve", "--addr", "0.0.0.0:8080"]
