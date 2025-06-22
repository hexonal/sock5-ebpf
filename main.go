package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"linuxService/pkg/interceptor"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	verbose         bool
	cleanupInterval string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.WithError(err).Fatal("命令执行失败")
	}
}

var rootCmd = &cobra.Command{
	Use:   "wx-proxy",
	Short: "容器内eBPF流量监控服务",
	Long:  `使用eBPF技术在容器内监控linuxService流量，捕获SOCKS5认证信息`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runContainerEbpfMonitor(cmd, args); err != nil {
			logrus.WithError(err).Fatal("容器内eBPF监控启动失败")
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "详细日志输出")
	rootCmd.PersistentFlags().StringVar(&cleanupInterval, "cleanup-interval", "1h", "日志清理间隔时间 (例如: 30m, 1h, 2h)")
	rootCmd.PersistentFlags().Bool("container-mode", false, "容器内监控模式")

	// 容器内eBPF监控模式命令参数
	rootCmd.Flags().String("program", "./socks5_monitor_container.o", "eBPF程序文件路径")
	rootCmd.Flags().Duration("stats-interval", 30*time.Second, "统计报告间隔")
}

func setupLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.SetOutput(os.Stdout)
}

// runContainerEbpfMonitor 启动容器内eBPF流量监控模式
func runContainerEbpfMonitor(cmd *cobra.Command, args []string) error {
	// 初始化日志
	setupLogger()

	logrus.Info("🚀 启动容器内eBPF流量监控模式...")
	logrus.Info("🎯 核心功能：监听linuxService目标程序的出站流量，捕获SOCKS5认证信息")
	logrus.Info("💡 容器内监控：无需host网络，最小权限运行")

	// 获取配置（优先使用环境变量，其次命令行参数）
	program := getEnvString("EBPF_PROGRAM", cmd, "program", "./socks5_monitor_container.o")
	containerMode := getEnvBool("CONTAINER_MODE", cmd, "container-mode", true)
	statsInterval := getEnvDuration("STATS_INTERVAL", cmd, "stats-interval", 30*time.Second)

	logrus.WithFields(logrus.Fields{
		"program":        program,
		"container_mode": containerMode,
		"stats_interval": statsInterval,
	}).Info("📋 容器内eBPF监控器配置")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动日志清理器（每5分钟清理一次）
	go startLogCleaner(ctx)

	// 创建容器内eBPF监控器
	ebpfMonitor, err := interceptor.NewEbpfMonitor(program, "")
	if err != nil {
		logrus.WithError(err).Fatal("❌ 创建容器内eBPF监控器失败")
	}

	// 监听信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logrus.WithField("signal", sig).Info("🛑 接收到退出信号，正在关闭...")
		cancel()
	}()

	// 启动容器内eBPF监控器
	return ebpfMonitor.Start(ctx, statsInterval)
}

// startLogCleaner 启动日志清理器
func startLogCleaner(ctx context.Context) {
	logrus.Info("🧹 启动日志清理器 - 每5分钟清理一次logs/*")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("🧹 日志清理器退出")
			return
		case <-ticker.C:
			cleanLogs()
		}
	}
}

// cleanLogs 清理日志文件
func cleanLogs() {
	logsDir := "./logs"
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		// 如果日志目录不存在，先创建
		if err := os.MkdirAll(logsDir, 0755); err != nil {
			logrus.WithError(err).Error("❌ 创建日志目录失败")
			return
		}
		logrus.Debug("📁 创建日志目录")
		return
	}

	entries, err := os.ReadDir(logsDir)
	if err != nil {
		logrus.WithError(err).Error("❌ 读取日志目录失败")
		return
	}

	cleaned := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(logsDir, entry.Name())
		if err := os.Remove(filePath); err != nil {
			logrus.WithError(err).WithField("file", entry.Name()).Warn("⚠️ 删除日志文件失败")
		} else {
			cleaned++
			logrus.WithField("file", entry.Name()).Debug("🗑️ 删除日志文件")
		}
	}

	if cleaned > 0 {
		logrus.WithField("count", cleaned).Info("🧹 清理日志文件完成")
	} else {
		logrus.Debug("🧹 无需清理，日志目录为空")
	}
}

// getEnvString 从环境变量获取字符串配置
func getEnvString(envKey string, cmd *cobra.Command, flagName string, defaultValue string) string {
	if envValue := os.Getenv(envKey); envValue != "" {
		return envValue
	}

	if cmd.Flags().Changed(flagName) {
		if value, err := cmd.Flags().GetString(flagName); err == nil {
			return value
		}
	}

	return defaultValue
}

// getEnvDuration 从环境变量获取时间间隔配置
func getEnvDuration(envKey string, cmd *cobra.Command, flagName string, defaultValue time.Duration) time.Duration {
	if envValue := os.Getenv(envKey); envValue != "" {
		duration, err := time.ParseDuration(envValue)
		if err == nil {
			return duration
		}
		logrus.WithError(err).WithField("env_key", envKey).WithField("value", envValue).Warn("解析环境变量失败，使用默认值")
	}

	if cmd.Flags().Changed(flagName) {
		if value, err := cmd.Flags().GetDuration(flagName); err == nil {
			return value
		}
	}

	return defaultValue
}

// getEnvBool 从环境变量获取布尔配置
func getEnvBool(envKey string, cmd *cobra.Command, flagName string, defaultValue bool) bool {
	if envValue := os.Getenv(envKey); envValue != "" {
		value, err := strconv.ParseBool(envValue)
		if err == nil {
			return value
		}
		logrus.WithError(err).WithField("env_key", envKey).WithField("value", envValue).Warn("解析环境变量失败，使用默认值")
	}

	if cmd.Flags().Changed(flagName) {
		if value, err := cmd.Flags().GetBool(flagName); err == nil {
			return value
		}
	}

	return defaultValue
}

// getEnvInt 从环境变量获取整数配置
func getEnvInt(envKey string, cmd *cobra.Command, flagName string, defaultValue int) int {
	if envValue := os.Getenv(envKey); envValue != "" {
		value, err := strconv.Atoi(envValue)
		if err == nil {
			return value
		}
		logrus.WithError(err).WithField("env_key", envKey).WithField("value", envValue).Warn("解析环境变量失败，使用默认值")
	}

	if cmd.Flags().Changed(flagName) {
		if value, err := cmd.Flags().GetInt(flagName); err == nil {
			return value
		}
	}

	return defaultValue
}
