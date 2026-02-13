# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /nonce ./cmd/nonce

# Run stage
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /nonce /nonce
USER 65534:65534
ENTRYPOINT ["/nonce"]
