FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
COPY packages/connectors/go.mod packages/connectors/go.sum ./
RUN go mod download
COPY packages/connectors/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /connector-auth ./cmd/connector-auth

FROM cgr.dev/chainguard/static:latest@sha256:399c8cb4858f05aaa33f43f02a2e75f28d40f016c0f86e5ba6075769e3303791
COPY --from=build /connector-auth /connector-auth
USER 65532:65532
EXPOSE 8094
ENTRYPOINT ["/connector-auth"]
