.PHONY: build
build: genfnatbpf
	go build -o ./bin/warp ./cmd/warp/main.go
	go build -o ./bin/warpd ./cmd/warpd/main.go

.PHONY: genfnatbpf
genfnatbpf:
	clang \
	-Wall \
	-I./ebpf/include \
	-O2 -emit-llvm -c ./ebpf/warp_fnat.c -o -| llc -march=bpf -filetype=obj -o ./bin/fnat_bpfel.o