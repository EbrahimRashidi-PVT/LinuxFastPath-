.PHONY: generate test build run clean

IFACE ?= veth-host

generate:
	go generate ./...

test:
	go test ./...

build: generate
	go build -o bin/tcxmon ./tcxmon

run: build
	sudo ./bin/tcxmon -iface $(IFACE)

clean:
	rm -rf bin tcxmon/tcx_bpfel.go tcxmon/tcx_bpfel.o tcxmon/tcx_bpfeb.go tcxmon/tcx_bpfeb.o
