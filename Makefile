.PHONY: build clean

APP_NAME=tvault-core
MAIN_PATH=./cmd/

help:
	@echo "Available commands:"
	@echo "  make build        - Build the application"
	@echo "  make clean        - Remove build artifacts"

build:
	go build -o $(APP_NAME) $(MAIN_PATH)

clean:
	rm -f $(APP_NAME)
	rm -f ./debug/profiles/*.prof
	rm -f ./debug/profiles/*.out
	rm -f *.log
	rm -f *.json
	rm -f *.txt
