package interceptor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// ContainerMonitor 容器内linuxService监控器（专注、简化、高性能）
type ContainerMonitor struct {
	programPath     string // eBPF程序路径
	logger          *logrus.Entry
	linuxServiceCmd *exec.Cmd // linuxService 进程命令
	linuxServicePID int       // linuxService 进程 PID
}

// NewEbpfMonitor 创建新的容器内监控器
func NewEbpfMonitor(programPath, interfaceName string) (*ContainerMonitor, error) {
	// 检查eBPF程序文件是否存在
	if _, err := os.Stat(programPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("eBPF程序文件不存在: %s", programPath)
	}

	return &ContainerMonitor{
		programPath: programPath,
		logger: logrus.WithFields(logrus.Fields{
			"component": "container-monitor",
			"program":   filepath.Base(programPath),
		}),
	}, nil
}

// Start 启动容器内监控
func (c *ContainerMonitor) Start(ctx context.Context, statsInterval time.Duration) error {
	c.logger.Info("🚀 启动容器内linuxService监控器...")
	c.logger.Info("🎯 专注功能：监控容器内linuxService进程的*.qq.com流量和SOCKS5认证")

	// 启动 linuxService 并获取 PID
	if err := c.startLinuxService(ctx); err != nil {
		return fmt.Errorf("启动linuxService失败: %w", err)
	}

	// 启动增强SOCKS5监控（核心功能）
	go c.startEnhancedSOCKS5Monitor(ctx, statsInterval)

	// 启动状态报告器
	go c.startStatusReporter(ctx, statsInterval)

	c.logger.WithField("linux_service_pid", c.linuxServicePID).Info("✅ 容器内监控器启动完成")

	// 等待上下文取消
	<-ctx.Done()
	c.logger.Info("🛑 容器内监控器开始退出...")

	// 清理 linuxService 进程
	c.stopLinuxService()
	c.logger.Info("📤 容器内监控器退出")
	return nil
}

// startLinuxService 启动 linuxService 程序
func (c *ContainerMonitor) startLinuxService(ctx context.Context) error {
	c.logger.Info("🔧 启动linuxService目标程序...")

	// 检查linuxService可执行文件
	if _, err := os.Stat("./linuxService"); os.IsNotExist(err) {
		return fmt.Errorf("linuxService可执行文件不存在")
	}

	// 创建命令
	c.linuxServiceCmd = exec.CommandContext(ctx, "./linuxService")

	// 设置环境变量
	c.linuxServiceCmd.Env = append(os.Environ(),
		"REDIS_HOST=redis",
		"REDIS_PORT=6379",
		"REDIS_PASSWORD=12399999",
		"LOG_LEVEL=error",
	)

	// 设置进程组
	c.linuxServiceCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// 重定向日志到文件
	logFile, err := os.OpenFile("logs/linuxService.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.logger.WithError(err).Warn("⚠️ 无法创建linuxService日志文件")
	} else {
		c.linuxServiceCmd.Stdout = logFile
		c.linuxServiceCmd.Stderr = logFile
	}

	// 启动进程
	if err := c.linuxServiceCmd.Start(); err != nil {
		return fmt.Errorf("启动linuxService进程失败: %w", err)
	}

	// 获取 PID
	c.linuxServicePID = c.linuxServiceCmd.Process.Pid
	c.logger.WithField("pid", c.linuxServicePID).Info("✅ linuxService进程启动成功")

	// 监控进程状态
	go c.monitorLinuxServiceProcess(ctx)

	return nil
}

// monitorLinuxServiceProcess 监控 linuxService 进程状态
func (c *ContainerMonitor) monitorLinuxServiceProcess(ctx context.Context) {
	if c.linuxServiceCmd == nil {
		return
	}

	err := c.linuxServiceCmd.Wait()
	if err != nil && ctx.Err() == nil {
		c.logger.WithError(err).Warn("⚠️ linuxService进程异常退出")
	}
	c.linuxServicePID = 0
}

// stopLinuxService 停止 linuxService 进程
func (c *ContainerMonitor) stopLinuxService() {
	if c.linuxServiceCmd == nil || c.linuxServiceCmd.Process == nil {
		return
	}

	c.logger.WithField("pid", c.linuxServicePID).Info("🛑 停止linuxService进程...")

	// 发送 SIGTERM 信号
	if err := c.linuxServiceCmd.Process.Signal(syscall.SIGTERM); err != nil {
		c.linuxServiceCmd.Process.Kill()
	}

	// 等待进程退出
	done := make(chan error, 1)
	go func() {
		done <- c.linuxServiceCmd.Wait()
	}()

	select {
	case <-time.After(5 * time.Second):
		c.linuxServiceCmd.Process.Kill()
	case <-done:
		c.logger.Info("✅ linuxService进程已停止")
	}
}

// startEnhancedSOCKS5Monitor 启动增强SOCKS5监控（核心功能）
func (c *ContainerMonitor) startEnhancedSOCKS5Monitor(ctx context.Context, interval time.Duration) {
	c.logger.Info("🔐 启动增强SOCKS5监控（专注linuxService进程）...")

	// 创建增强SOCKS5监控器，专注于linuxService进程
	monitor := NewEnhancedSOCKS5Monitor(c.linuxServicePID)

	// 启动定时清理和检查
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("📤 增强SOCKS5监控退出")
			return
		case <-ticker.C:
			// 清理过期会话
			monitor.CleanupSessions()
		}
	}
}

// startStatusReporter 启动状态报告器
func (c *ContainerMonitor) startStatusReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("📤 状态报告器退出")
			return
		case <-ticker.C:
			c.reportStatus()
		}
	}
}

// reportStatus 报告监控状态
func (c *ContainerMonitor) reportStatus() {
	isRunning := c.linuxServicePID > 0 && c.linuxServiceCmd != nil && c.linuxServiceCmd.Process != nil

	if !isRunning {
		c.logger.WithField("alert", "LINUX_SERVICE_DOWN").Error("❌ linuxService进程未运行")
	} else {
		c.logger.WithFields(logrus.Fields{
			"alert":             "CONTAINER_MONITORING_ACTIVE",
			"linux_service_pid": c.linuxServicePID,
			"monitoring_status": "active",
			"container_mode":    true,
		}).Info("✅ 容器内监控活跃 - 专注linuxService进程")
	}
}

// GetLinuxServicePID 获取linuxService的PID
func (c *ContainerMonitor) GetLinuxServicePID() int {
	return c.linuxServicePID
}
