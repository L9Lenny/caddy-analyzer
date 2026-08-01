# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s -X github.com/L9Lenny/caddy-analyzer/cmd.Version=${VERSION}" -o caddy-analyze ./cmd/caddy-analyze

# Production Stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/caddy-analyze /usr/local/bin/caddy-analyze

ENTRYPOINT ["caddy-analyze"]
CMD ["--help"]
