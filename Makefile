# branch/commit_hash/tag to build with containers
COMMIT ?= master
NETWORK ?=mainnet

.PHONY: clean

clean:
	@echo "Cleaning build artifacts"
	rm -rf server
	docker container rm -f go-relayer-temp
	docker rmi -f go-relayer-build

build: clean
	@echo "Building relayer binary in container with local source files"
	docker build --no-cache --build-arg commit=$(COMMIT) -t go-relayer-build .
	docker container create --name go-relayer-temp go-relayer-build
	docker container cp go-relayer-temp:/workspace/server .
	sha256sum server
