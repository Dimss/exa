build:
	go build -ldflags="-X 'github.com/Dimss/exa/authz/cmd/cmd.Build=$$(git rev-parse --short HEAD)'" -o bin/exa cmd/authz/main.go