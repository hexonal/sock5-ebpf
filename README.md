# wx-proxy eBPF内核级网络流量监控服务

这是一个基于 Go 和 eBPF 技术的内核级网络流量监控服务，专门用于监控 `linuxService` 目标程序的出站流量，实时捕获 SOCKS5 代理认证信息。

## 功能特性

- **eBPF内核级监控**: 使用 eBPF 技术在内核层面直接捕获网络事件
- **目标程序监控**: 专门监控 `linuxService` 可执行程序的出站流量
- **SOCKS5 认证捕获**: 实时捕获用户名、密码等认证信息
- **高性能**: 零延迟、低开销的内核级数据包处理
- **自动降级**: eBPF 不可用时自动降级到连接监控模式
- **内核兼容性**: 支持多个版本的 eBPF 程序（标准版和兼容版）
- **日志清理**: 自动清理日志文件，防止磁盘空间耗尽

## 工作原理

1. **启动阶段**:
   - `wx-proxy` 主服务启动
   - 检测 `linuxService` 目标程序是否存在
   - 编译或加载 eBPF 程序到内核

2. **监控阶段**:
   - eBPF 程序在内核层面监听网络事件
   - 实时检测 SOCKS5 协议数据包
   - 捕获认证信息（用户名、密码、代理服务器地址等）

3. **数据处理**:
   - 认证信息处理器记录捕获的数据
   - 生成审计日志用于安全分析
   - 可扩展的业务处理接口

## 安装和使用

### 构建镜像

```bash
cd linuxService
docker build -t wx-proxy .
```

### 运行容器

```bash
# eBPF 监控模式（推荐）
docker run --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN wx-proxy

# 详细日志运行
docker run --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN wx-proxy ./wx-proxy --verbose
```

**注意**: 必须使用 `--privileged` 或相应的 capabilities，因为 eBPF 需要内核权限。

### 🐛 Debug模式（专注流量拦截监控）

Debug模式已优化，专注于显示关键的流量拦截状态：

```bash
# 使用docker-compose启动Debug模式
docker-compose up wx-proxy

# 预期的关键日志输出
✅ [OK] linuxService进程运行中 - 流量监控活跃
🌐 [Success] 成功拦截到出站流量  
🔐 [Success] 已捕获SOCKS5认证信息
🎯 [QQ域名] 检测到QQ域名相关流量
```

**Debug模式特性：**
- ✅ **Redis自动连接**: 6379端口已放行，自动连接Redis服务
- ✅ **日志分离**: linuxService日志重定向到`logs/linuxService.log`（避免控制台干扰）
- ✅ **实时监控**: 10秒间隔的流量拦截状态报告
- ✅ **专注显示**: 只显示流量拦截和SOCKS5认证相关的关键日志
- ✅ **状态清晰**: 使用Alert标签区分不同状态（OK/Success/Waiting/Alert）
- ✅ **SOCKS5深度分析**: 专门分析QQ域名流量中的SOCKS5协议，解析用户名和密码

### 本地运行

```bash
# 默认 eBPF 监控模式
sudo ./wx-proxy --verbose

# 指定 eBPF 程序文件
sudo ./wx-proxy --program=./socks5_monitor.o --interface=eth0

# 透明代理模式
sudo ./wx-proxy transparent-interceptor --redirect-port=8080
```

## 命令行参数

```bash
./wx-proxy [flags]

Flags:
  --program string         eBPF程序文件路径 (默认 "./socks5_monitor_default.o")
  --interface string       网络接口名称 (留空表示所有接口)
  --stats-interval duration 统计报告间隔 (默认 30s)
  -v, --verbose           详细日志输出
  -h, --help             帮助信息

Commands:
  transparent-interceptor  启动透明代理拦截模式
```

## eBPF 程序版本

项目包含三个版本的 eBPF 程序：

- **`socks5_monitor.o`**: 标准版本（功能完整）
- **`socks5_monitor_compat.o`**: 兼容版本（移除不兼容函数）
- **`socks5_monitor_default.o`**: 默认版本（链接到兼容版本）

系统会自动选择最适合的版本，确保在不同内核版本上的兼容性。

## 监控和日志

### SOCKS5 认证信息捕获
```log
WARN[...] 🔐 [SOCKS5认证信息捕获] 检测到代理认证
  username=user123
  password_masked=***23
  proxy_addr=192.168.1.100
  proxy_port=1080
  target_addr=example.com
  target_port=443
  from_linux_service=true
```

### 统计信息
每 30 秒输出一次监控统计：
```log
INFO[...] 📈 监控器运行状态
  component=stats
  program=socks5_monitor_default.o
  mode=eBPF内核级
  captured_credentials=5
```

### 日志级别
- **DEBUG**: 详细的 eBPF 和网络事件信息
- **INFO**: 基本的运行状态和统计信息
- **WARN**: 捕获的认证信息和警告
- **ERROR**: 错误和异常情况

## 安全考虑

1. **权限要求**: 需要 root 权限来加载 eBPF 程序
2. **内核兼容性**: 需要支持 eBPF 的 Linux 内核 (>= 4.1)
3. **敏感信息**: 注意保护捕获的认证信息
4. **资源监控**: 监控内核内存使用情况

## 故障排除

### 常见问题

1. **eBPF 不支持**:
   ```
   WARN[...] ⚠️ eBPF监控器启动失败，切换到降级模式
   ```
   解决: 检查内核版本和 eBPF 支持

2. **权限不足**:
   ```
   ERROR: 创建eBPF内核级流量监控器失败
   ```
   解决: 确保使用 `sudo` 或 `--privileged` 运行

3. **目标程序未找到**:
   ```
   ERROR: linuxService可执行文件不存在
   ```
   解决: 确保 `linuxService` 文件存在并可执行

### 调试模式

启用详细日志进行调试：
```bash
sudo ./wx-proxy --verbose
```

检查 eBPF 支持：
```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/fs/bpf/
```

## 限制和已知问题

1. **内核依赖**: 需要支持 eBPF 的现代 Linux 内核
2. **TCP 协议**: 主要针对 TCP 流量，UDP 支持有限
3. **权限要求**: 必须在特权模式下运行
4. **目标程序**: 专门监控 `linuxService`，其他程序需要修改配置

## 开发和贡献

### 目录结构
```
linuxService/
├── main.go              # 主入口文件 (wx-proxy)
├── go.mod              # Go 模块定义
├── pkg/                # 核心包
│   ├── interceptor/    # eBPF 监控器
│   ├── detector/       # SOCKS5 检测器
│   └── cleaner/        # 日志清理器
├── ebpf-traffic-monitor/ # eBPF 程序源码
├── Dockerfile          # Docker 构建文件
├── linuxService        # 目标监控程序
└── README.md          # 说明文档
```

### 依赖库
- `github.com/florianl/go-nfqueue`: netfilter queue 接口
- `github.com/google/gopacket`: 数据包解析
- `github.com/sirupsen/logrus`: 日志记录
- `github.com/spf13/cobra`: 命令行框架

## 许可证

本项目采用 MIT 许可证。 