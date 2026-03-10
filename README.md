# Pangee-VXIP

## 项目介绍
Pangee-VXIP 基于四层网络隧道技术，通过独立的 FullNAT 网关，实现跨资源池应用通过四层网络隧道互访的能力。

#### 软件架构
软件架构如下图所示：
![架构图](resource/arch.png?raw=true)

- **内核态**：基于 eBPF 框架实现网络转发的数据平面。通过 eBPF 的 XDP 程序对到达网卡的数据包进行实时筛选，并完成网络地址转换与转发处理。
- **用户态**：包含多个核心模块：
  - **Interface Attach**：管理 eBPF 程序的挂载与卸载；
  - **IP Port Mapping**：管理数据包的筛选规则与转发规则；
  - **Session Management**：负责会话生命周期的管理；
  - **NetRaw Ping**：通过 ping 方式实现 ARP 学习；
  - **Configuration**：配置管理模块；
  - **gRPC Server**：提供 gRPC 服务接口。
- **API 层**：提供本地运维工具（命令行方式）以及远程调用的 gRPC 接口。

#### 安装教程

##### 配置文件说明
```yaml
global:
  fnat-filepath: /app/warp/bin/fnat_bpfel.o   # eBPF 文件挂载路径（使用 Docker 镜像时请勿修改）
  conn-timeout: 5                              # 非活跃连接的超时时间（秒）
  available-port-range:                         # 主机可用端口范围
    min: 10000
    max: 45191

fnat:
  attached:                                     # 挂载网卡的 IP 地址
    - 192.168.20.1
    - 192.168.40.1
  services:                                      # 服务映射规则
    - virtual-ip: 192.168.20.1                   # 目的 IP（若在子接口过滤，请按“目的IP/父接口IP”格式填写）
      virtual-port: 8080                          # 目的端口
      protocol: tcp                               # 协议类型
      local-ip: 192.168.40.1                      # 本地转发接口 IP
      real-port: 8080                             # 实际转发端口
      real-server-ips:                            # 后端服务器 IP（支持多 IP，采用轮询负载均衡）
        - 192.168.40.22
```

##### 打包镜像
请确保已安装 Docker Engine，并能下载以下镜像：
- `ubuntu:22.04`

在项目根目录下执行以下命令构建镜像：
```bash
docker build -t warp:latest -f docker/Dockerfile .
```

##### 部署镜像
启动容器需使用 `privileged` 权限并启用主机网络模式。

部署命令示例：
```bash
docker run --name=warp --network=host --privileged=true -v /opt/conf:/app/warp/conf -d warp:latest
```
> 注意：主机目录 `/opt/conf` 下需包含 `warp.yaml` 配置文件。

#### 使用说明

##### 远程接口调用
详细接口定义请参考 [warp.proto](./api/warp.proto)。

##### 本地工具
执行以下命令查看本地工具的使用帮助：
```bash
warp -h
```