# Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o caddy-analyze ./cmd/caddy-analyze

# Production Stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/caddy-analyze /usr/local/bin/caddy-analyze

ENTRYPOINT ["caddy-analyze"]
CMD ["--help"]
