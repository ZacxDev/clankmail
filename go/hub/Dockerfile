# ClankMail hub image. Build from the REPO ROOT (the hub module replaces
# github.com/ZacxDev/clankmail with ../.., so the root module is needed):
#
#   docker build -f go/hub/Dockerfile -t clankmail-hub:dev .
#   docker run --rm -p 8080:8080 -v hubdata:/data clankmail-hub:dev -hub hub.example
#
# modernc.org/sqlite is pure Go, so the binary is static (CGO_ENABLED=0).
FROM golang:1.24-bookworm AS build
WORKDIR /src
# Module files first, for a cached dependency layer.
COPY go.mod ./
COPY go/hub/go.mod go/hub/go.sum ./go/hub/
RUN cd go/hub && go mod download
COPY go/clankmail ./go/clankmail
COPY go/hub ./go/hub
RUN cd go/hub && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clankmail-hub ./cmd/clankmail-hub \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/clankmail-hub /clankmail-hub
# The database lives here; mount a volume to keep it.
COPY --from=build --chown=nonroot:nonroot /out/data /data
VOLUME /data
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/clankmail-hub", "-addr", ":8080", "-db", "/data/clankmail-hub.db"]
