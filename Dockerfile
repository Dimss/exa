# Build the manager binary
FROM golang:1.22.3 as builder
ARG buildsha
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN go build -ldflags="-X 'github.com/Dimss/exa/authz/cmd/cmd.Build=${buildsha}'" -o exa cmd/authz/main.go

FROM debian:bookworm-slim
WORKDIR /opt/app-root
COPY --from=builder /workspace/exa .