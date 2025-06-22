# 容器内eBPF监控 - 最小权限版本
FROM golang:1.24-alpine AS builder
WORKDIR /app
# 使用中国大陆APK源加速包下载
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk update

# 安装容器内eBPF构建依赖（最小化）
RUN apk add --no-cache \
    git gcc musl-dev linux-headers \
    clang llvm libbpf-dev make \
    binutils file

# 配置多个代理源作为备选
ENV GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://goproxy.io,direct
ENV GOTIMEOUT=300s

COPY . .

# 构建 wx-proxy 容器内监控器（Go 部分）
RUN echo "🔧 构建wx-proxy容器内监控器..." && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o wx-proxy main.go && \
    echo "✅ wx-proxy容器内监控器构建成功" && \
    file wx-proxy

# 编译容器内eBPF程序
RUN echo "🔧 编译容器内eBPF程序..." && \
    mkdir -p build && \
    \
    echo "📦 编译容器版本..." && \
    clang -O2 -g -Wall \
    -I/usr/include \
    -I/usr/include/bpf \
    -I/usr/include/linux \
    -target bpf \
    -D CONTAINER_MODE=1 \
    -c socks5_monitor_container.c \
    -o build/socks5_monitor_container.o && \
    echo "✅ 容器版本编译成功" && \
    file build/socks5_monitor_container.o

# 验证 linuxService 目标可执行程序（wx-proxy将启动此程序并监控其出站流量）
RUN echo "🔍 验证 linuxService 目标可执行程序..." && \
    ls -la linuxService && \
    file linuxService && \
    echo "✅ linuxService 目标程序验证完成"

# 准备最终部署
RUN echo "🔍 验证构建文件..." && \
    ls -la wx-proxy linuxService && \
    echo "✅ 所有文件准备完成"

# 运行镜像 - 使用轻量级Ubuntu镜像
FROM ubuntu:22.04

# 设置时区和语言环境
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 使用阿里云镜像源加速
RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list && \
    sed -i 's@//.*security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list

# 安装容器内eBPF运行时环境（最小化）
RUN apt-get update && apt-get install -y \
    # 基础工具
    ca-certificates \
    curl \
    # 网络工具
    iproute2 \
    netcat \
    # 容器内eBPF运行时（最小化）
    libbpf0 \
    # 进程工具
    procps \
    # 清理缓存
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建eBPF文件系统挂载点
RUN mkdir -p /sys/fs/bpf && \
    mkdir -p /sys/kernel/debug

# wx-proxy 主服务运行目录
WORKDIR /app

# 复制主服务、linuxService目标程序和eBPF程序
COPY --from=builder /app/wx-proxy .
COPY --from=builder /app/linuxService .
COPY --from=builder /app/build/socks5_monitor_container.o .

# 设置执行权限
RUN chmod +x ./wx-proxy ./linuxService

# 创建日志目录
RUN mkdir -p /app/logs

# 添加容器标签  
LABEL description="容器内eBPF流量监控服务，专门监控linuxService程序的容器内流量"
LABEL usage="docker run --cap-add SYS_ADMIN --cap-add NET_ADMIN wx-proxy"
LABEL features="容器内eBPF监控,SOCKS5认证捕获,QQ域名监控,最小权限运行"

# 设置环境变量
ENV VERBOSE=true \
    EBPF_PROGRAM=./socks5_monitor_container.o \
    STATS_INTERVAL=30s \
    CLEANUP_INTERVAL=1h \
    CONTAINER_MODE=true

# 容器内eBPF监控功能：
# - 容器内eBPF监控：只监控容器内的网络流量
# - 最小权限运行：只需要SYS_ADMIN和NET_ADMIN权限
# - Bridge网络：使用标准Docker网络，无需host模式
# - 无AppArmor冲突：避免host级别的权限需求
#
# 核心功能：
# - 自动启动linuxService目标程序并获取PID
# - 使用eBPF监控容器内指定PID的网络流量
# - 专门监控*.qq.com域名流量
# - 捕获SOCKS5认证信息（用户名+密码）
# - 容器内流量完整分析
#
# 技术优势：
# - 容器内完整监控：无需host网络访问
# - 最小权限原则：只添加必需的capabilities
# - 无AppArmor冲突：避免系统级权限问题
# - Bridge网络兼容：标准Docker网络环境

# 默认启动容器内eBPF监控模式
CMD ["./wx-proxy", "--verbose", "--container-mode"] 
