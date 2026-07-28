# Contributing to caddy-analyzer

Thank you for your interest in contributing to `caddy-analyzer`! We welcome contributions from everyone.

## Development Setup

1. Prerequisites: [Go](https://go.dev) (v1.22+).
2. Clone the repository:
   ```bash
   git clone https://github.com/lenny/caddy-analyzer.git
   cd caddy-analyzer
   ```
3. Run tests:
   ```bash
   go test -v ./...
   ```
4. Build binary:
   ```bash
   go build -o caddy-analyze ./cmd/caddy-analyze
   ```

## Pull Request Guidelines

- Ensure all existing tests pass (`go test ./...`).
- Add unit tests for any new features or security signatures.
- Keep commits clean and descriptive.
