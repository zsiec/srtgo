# Contributing to srtgo

Thank you for your interest in contributing to srtgo!

## Bug Reports

Please open a [GitHub issue](https://github.com/zsiec/srtgo/issues) with:

- Go version (`go version`)
- Operating system and architecture
- Minimal reproduction steps
- Expected vs. actual behavior

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Run tests: `make test` or `go test -race ./...`
5. Run linting: `go vet ./...`
6. Commit with a clear message
7. Open a pull request

## Code Style

- Format code with `gofmt`
- Pass `go vet` with no warnings
- Add tests for new functionality
- Keep changes focused — one feature or fix per PR

## Testing

```bash
# Run all tests with race detection
go test -race -count=1 -timeout 120s ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Run a specific package's tests
go test -race ./internal/buffer/...
```

## Development Notes

- srtgo has zero external dependencies (stdlib + `golang.org/x/crypto` only)
- Internal packages under `internal/` are not part of the public API
- When in doubt, match behavior with the [C++ SRT reference implementation](https://github.com/Haivision/srt)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
