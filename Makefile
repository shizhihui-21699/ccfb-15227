GO ?= go
BIN := bin

.PHONY: all build test race vet fmt lint validate simulate e2e clean

all: build

build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/admissiond ./cmd/admissiond
	$(GO) build -trimpath -o $(BIN)/admissionctl ./cmd/admissionctl

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

# validate is the CI gate: a policy that does not compile must never merge.
validate: build
	./$(BIN)/admissionctl validate-policies --policy-dir testdata/policies

simulate: build
	./$(BIN)/admissionctl simulate --policy-dir testdata/policies \
		--manifest testdata/manifests/workloads.yaml \
		--namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"

e2e: build
	./$(BIN)/admissionctl e2e --policy-dir testdata/policies \
		--manifest testdata/manifests/workloads.yaml \
		--namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"

clean:
	rm -rf $(BIN)
