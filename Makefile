ifdef CIRCLECI
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LDFLAGS=-linkmode external -extldflags -static
	endif
endif

.PHONY: help
help:  ## Print the help documentation
	@grep -E '^[/a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

bin/find-guardduty-user: ## Build find-guardduty-user
	go build -ldflags "$(LDFLAGS)" -o bin/find-guardduty-user .

.PHONY: release
release: ## Build the project artifacts for release
	docker run -v "${PWD}:/home/circleci/project" -w "/home/circleci/project" cibuilds/github:0.10 ./scripts/release.sh

.PHONY: clean
clean: ## Clean all generated files
	rm -rf ./artifacts
	rm -rf ./bin

default: help
