# Build the Quietly home server, trust service, or federation gateway.
#
# The build context MUST be the parent directory that contains both
# `quietly-crypto` and `quietly-server`, because the server's go.mod references
# quietly-crypto via a local `replace` directive (../quietly-crypto).
#
#   docker build -f quietly-server/Dockerfile -t quietly-server --build-arg COMPONENT=server .
#
ARG COMPONENT=server

FROM golang:1.26-alpine AS build
ARG COMPONENT
WORKDIR /src
COPY quietly-crypto/ ./quietly-crypto/
COPY quietly-server/ ./quietly-server/
WORKDIR /src/quietly-server
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${COMPONENT}

FROM alpine:3.20
RUN adduser -D -u 10001 quietly
COPY --from=build /out/app /usr/local/bin/quietly-app
USER quietly
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/quietly-app"]
