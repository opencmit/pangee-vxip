FROM ubuntu:22.04 AS builder

# 安装llvm
RUN apt update && \
    apt install -y llvm-11 clang-11 && \
    rm -rf /var/lib/apt/lists/*

# 安装Golang
RUN wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -O /tmp/go1.24.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf /tmp/go1.24.linux-amd64.tar.gz && \
    rm /tmp/go1.24.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV GOPROXY=https://goproxy.cn,direct

COPY . /build
WORKDIR /build

RUN mkdir cbin && \
    clang-11 \
    -Wall \
    -I./ebpf/include \
    -O2 -emit-llvm -c ./ebpf/warp_fnat.c -o -| llc-11 -march=bpf -filetype=obj -o ./cbin/fnat_bpfel.o
RUN mkdir gobin && \
    go env -w CGO_ENABLED=0 && \
    go build -o ./gobin/warpd ./cmd/warpd/main.go && chmod +x ./gobin/warpd && \
    go build -o ./gobin/warp ./cmd/warp/main.go && chmod +x ./gobin/warp


# 最终阶段
FROM ubuntu:22.04 AS final

# 从构建阶段拷贝运行文件
RUN useradd -m -s /bin/bash pangeevxip && \
    mkdir -p /pangee-vxip/bin && \
    mkdir -p /pangee-vxip/conf
COPY --from=builder /build/cbin/fnat_bpfel.o /build/gobin/warpd /build/gobin/warp /pangee-vxip/bin/
COPY ./docker/warpd.yaml /pangee-vxip/conf/

RUN setcap cap_net_raw+ep /pangee-vxip/bin/warpd && \
    chown -R pangeevxip:pangeevxip /pangee-vxip && \
    chmod +x /pangee-vxip/bin/warpd /pangee-vxip/bin/warp

USER pangeevxip
WORKDIR /pangee-vxip

ENTRYPOINT ["./bin/warpd", "-c", "./conf/warpd.yaml"]