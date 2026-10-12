FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build
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
