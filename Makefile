docker:
	#docker buildx build --platform linux/amd64 --build-arg buildsha=$$(git rev-parse --short HEAD) --push -t dimssss/exa:$$(git rev-parse --short HEAD) .
	docker buildx build --platform linux/amd64 --build-arg buildsha=$$(git rev-parse --short HEAD) --push -t dimssss/exa:latest .

build:
	go build -ldflags="-X 'github.com/Dimss/exa/authz/cmd/cmd.Build=$$(git rev-parse --short HEAD)'" -o bin/exa cmd/authz/main.go