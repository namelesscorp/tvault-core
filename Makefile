.PHONY: build clean

APP_NAME=tvault-core
MAIN_PATH=./cmd/

help:
	@echo "Available commands:"
	@echo "  make build        - Build the application"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make lint         - Run golang ci linter"
	@echo "  make sec          - Run golang security linter"
	@echo "  make uml          - Generate svg from puml"
	@echo "  make checkup      - full checkup app"

build:
	go build -o $(APP_NAME) $(MAIN_PATH)

clean:
	rm -f $(APP_NAME)
	rm -f ./debug/profiles/*.prof
	rm -f ./debug/profiles/*.out
	rm -f *.log
	rm -f *.json
	rm -f *.txt

uml:
	plantuml -tsvg docs/*.puml

lint:
	golangci-lint run ./...

sec:
	gosec run ./...

test:
	go test ./...

checkup:
	make build
	make lint
	make sec
	make test