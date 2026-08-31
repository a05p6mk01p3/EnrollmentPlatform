# Enrollment Platform — build orchestration.
# Generated OpenAPI code is produced by make generate and is never edited by hand.

OPENAPI_SPEC       := docs/Enrollment_Platform_OpenAPI_Contract_Draft_v0.1.6.yaml
OPENAPI_GEN_CONFIG := build/oapi-codegen.yaml
OPENAPI_CODEGEN    := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
GENERATED_API      := internal/generated/openapi/api.gen.go

.PHONY: generate fmt vet test build check

generate:
	go run $(OPENAPI_CODEGEN) -config $(OPENAPI_GEN_CONFIG) $(OPENAPI_SPEC)

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./...

check: fmt vet test build
