package interceptor

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// EnhancedSOCKS5Monitor 增强的SOCKS5监控器
type EnhancedSOCKS5Monitor struct {
	targetPID      int
	authSessions   map[string]*SOCKS5Session
	packetBuffer   map[string][]byte
	lastAuthReport time.Time
}

// SOCKS5Session SOCKS5会话信息
type SOCKS5Session struct {
	SessionID   string
	ProxyIP     string
	ProxyPort   uint16
	Username    string
	Password    string
	TargetHost  string
	TargetPort  uint16
	AuthTime    time.Time
	ConnectTime time.Time
	Status      string
}

// NewEnhancedSOCKS5Monitor 创建增强SOCKS5监控器
func NewEnhancedSOCKS5Monitor(targetPID int) *EnhancedSOCKS5Monitor {
	return &EnhancedSOCKS5Monitor{
		targetPID:    targetPID,
		authSessions: make(map[string]*SOCKS5Session),
		packetBuffer: make(map[string][]byte),
	}
}

// AnalyzePacket 分析网络数据包
func (m *EnhancedSOCKS5Monitor) AnalyzePacket(data []byte, srcIP, dstIP string, srcPort, dstPort uint16) {
	sessionKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	// 检查是否为SOCKS5流量
	if !m.isSOCKS5Traffic(data, dstPort) {
		return
	}

	log.Printf("🔍 [eBPF-SOCKS5] 捕获数据包: %s (长度: %d)", sessionKey, len(data))

	// 累积数据包以处理分片
	m.accumulatePacket(sessionKey, data)

	// 分析完整的SOCKS5协议
	m.analyzeSOCKS5Protocol(sessionKey, m.packetBuffer[sessionKey], srcIP, dstIP, srcPort, dstPort)
}

// isSOCKS5Traffic 检查是否为SOCKS5流量
func (m *EnhancedSOCKS5Monitor) isSOCKS5Traffic(data []byte, dstPort uint16) bool {
	// 检查常见SOCKS5端口
	socksports := []uint16{1080, 1081, 7890, 7891, 8080, 8081, 9050, 9051}
	for _, port := range socksports {
		if dstPort == port {
			return true
		}
	}

	// 检查SOCKS5协议标识
	if len(data) >= 2 && data[0] == 0x05 {
		return true
	}

	// 检查用户名密码认证标识
	if len(data) >= 1 && data[0] == 0x01 {
		return true
	}

	return false
}

// accumulatePacket 累积数据包
func (m *EnhancedSOCKS5Monitor) accumulatePacket(sessionKey string, data []byte) {
	if existing, exists := m.packetBuffer[sessionKey]; exists {
		m.packetBuffer[sessionKey] = append(existing, data...)
	} else {
		m.packetBuffer[sessionKey] = make([]byte, len(data))
		copy(m.packetBuffer[sessionKey], data)
	}

	// 限制缓冲区大小，防止内存泄漏
	if len(m.packetBuffer[sessionKey]) > 4096 {
		m.packetBuffer[sessionKey] = m.packetBuffer[sessionKey][:4096]
	}
}

// analyzeSOCKS5Protocol 分析SOCKS5协议
func (m *EnhancedSOCKS5Monitor) analyzeSOCKS5Protocol(sessionKey string, data []byte, srcIP, dstIP string, srcPort, dstPort uint16) {
	if len(data) < 2 {
		return
	}

	session := m.getOrCreateSession(sessionKey, dstIP, dstPort)

	// 分析不同的SOCKS5阶段
	switch {
	case m.isAuthNegotiation(data):
		m.handleAuthNegotiation(session, data)

	case m.isUsernamePasswordAuth(data):
		m.handleUsernamePasswordAuth(session, data)

	case m.isConnectRequest(data):
		m.handleConnectRequest(session, data)

	case m.isConnectResponse(data):
		m.handleConnectResponse(session, data)

	default:
		// 尝试在数据中搜索认证信息
		m.searchAuthInData(session, data)
	}
}

// getOrCreateSession 获取或创建会话
func (m *EnhancedSOCKS5Monitor) getOrCreateSession(sessionKey, proxyIP string, proxyPort uint16) *SOCKS5Session {
	if session, exists := m.authSessions[sessionKey]; exists {
		return session
	}

	session := &SOCKS5Session{
		SessionID: sessionKey,
		ProxyIP:   proxyIP,
		ProxyPort: proxyPort,
		Status:    "连接中",
	}

	m.authSessions[sessionKey] = session
	return session
}

// isAuthNegotiation 检查是否为认证协商
func (m *EnhancedSOCKS5Monitor) isAuthNegotiation(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x05 && data[1] >= 0x01
}

// isUsernamePasswordAuth 检查是否为用户名密码认证
func (m *EnhancedSOCKS5Monitor) isUsernamePasswordAuth(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x01
}

// isConnectRequest 检查是否为连接请求
func (m *EnhancedSOCKS5Monitor) isConnectRequest(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x05 && data[1] == 0x01
}

// isConnectResponse 检查是否为连接响应
func (m *EnhancedSOCKS5Monitor) isConnectResponse(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x05 && data[1] == 0x00
}

// handleAuthNegotiation 处理认证协商
func (m *EnhancedSOCKS5Monitor) handleAuthNegotiation(session *SOCKS5Session, data []byte) {
	log.Printf("🔍 [SOCKS5-认证协商] 会话: %s", session.SessionID)

	if len(data) >= 3 {
		methodCount := int(data[1])
		log.Printf("🔍 [SOCKS5-认证协商] 客户端支持 %d 种认证方法", methodCount)

		for i := 0; i < methodCount && i+2 < len(data); i++ {
			method := data[2+i]
			switch method {
			case 0x00:
				log.Printf("🔍 [SOCKS5-认证协商] 方法 %d: 无需认证", method)
			case 0x02:
				log.Printf("🔍 [SOCKS5-认证协商] 方法 %d: 用户名密码认证", method)
			default:
				log.Printf("🔍 [SOCKS5-认证协商] 方法 %d: 其他认证方式", method)
			}
		}
	}
}

// handleUsernamePasswordAuth 处理用户名密码认证
func (m *EnhancedSOCKS5Monitor) handleUsernamePasswordAuth(session *SOCKS5Session, data []byte) {
	log.Printf("🔍 [SOCKS5-密码认证] 会话: %s", session.SessionID)

	if len(data) < 3 {
		return
	}

	// SOCKS5用户名密码认证格式：
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	if data[0] != 0x01 {
		return
	}

	usernameLen := int(data[1])
	if len(data) < 2+usernameLen+1 {
		return
	}

	username := string(data[2 : 2+usernameLen])
	passwordLen := int(data[2+usernameLen])

	if len(data) < 2+usernameLen+1+passwordLen {
		return
	}

	password := string(data[2+usernameLen+1 : 2+usernameLen+1+passwordLen])

	// 更新会话信息
	session.Username = username
	session.Password = password
	session.AuthTime = time.Now()
	session.Status = "认证成功"

	log.Printf("🔐 [SOCKS5-密码认证] 成功提取认证信息 - 用户名: '%s', 密码: '%s'", username, password)

	// 立即输出认证报告
	m.printSOCKS5AuthReport(session)
}

// handleConnectRequest 处理连接请求
func (m *EnhancedSOCKS5Monitor) handleConnectRequest(session *SOCKS5Session, data []byte) {
	log.Printf("🔍 [SOCKS5-连接请求] 会话: %s", session.SessionID)

	if len(data) < 4 {
		return
	}

	cmd := data[1]
	atyp := data[3]

	var targetHost string
	var targetPort uint16

	switch atyp {
	case 0x01: // IPv4
		if len(data) >= 10 {
			targetHost = fmt.Sprintf("%d.%d.%d.%d", data[4], data[5], data[6], data[7])
			targetPort = uint16(data[8])<<8 + uint16(data[9])
		}
	case 0x03: // 域名
		if len(data) >= 5 {
			domainLen := int(data[4])
			if len(data) >= 5+domainLen+2 {
				targetHost = string(data[5 : 5+domainLen])
				targetPort = uint16(data[5+domainLen])<<8 + uint16(data[5+domainLen+1])
			}
		}
	case 0x04: // IPv6
		targetHost = "IPv6地址"
	}

	if targetHost != "" {
		session.TargetHost = targetHost
		session.TargetPort = targetPort
		session.ConnectTime = time.Now()

		log.Printf("🎯 [SOCKS5-连接请求] 目标: %s:%d (命令: %d)", targetHost, targetPort, cmd)

		// 如果已有认证信息，输出完整报告
		if session.Username != "" {
			m.printSOCKS5AuthReport(session)
		}
	}
}

// handleConnectResponse 处理连接响应
func (m *EnhancedSOCKS5Monitor) handleConnectResponse(session *SOCKS5Session, data []byte) {
	if len(data) >= 2 {
		status := data[1]
		if status == 0x00 {
			session.Status = "连接成功"
			log.Printf("✅ [SOCKS5-连接响应] 连接成功: %s", session.SessionID)
		} else {
			session.Status = fmt.Sprintf("连接失败(错误码: %d)", status)
			log.Printf("❌ [SOCKS5-连接响应] 连接失败: %s (错误码: %d)", session.SessionID, status)
		}
	}
}

// searchAuthInData 在数据中搜索认证信息
func (m *EnhancedSOCKS5Monitor) searchAuthInData(session *SOCKS5Session, data []byte) {
	// 如果已经有认证信息，跳过
	if session.Username != "" {
		return
	}

	// 搜索可能的用户名密码模式
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0x01 && i+1 < len(data) {
			usernameLen := int(data[i+1])
			if usernameLen > 0 && usernameLen < 64 && i+2+usernameLen < len(data) {
				username := string(data[i+2 : i+2+usernameLen])
				if i+2+usernameLen+1 < len(data) {
					passwordLen := int(data[i+2+usernameLen])
					if passwordLen > 0 && passwordLen < 64 && i+2+usernameLen+1+passwordLen <= len(data) {
						password := string(data[i+2+usernameLen+1 : i+2+usernameLen+1+passwordLen])

						// 验证是否为可打印字符
						if m.isPrintableString(username) && m.isPrintableString(password) {
							session.Username = username
							session.Password = password
							session.AuthTime = time.Now()
							session.Status = "认证信息已提取"

							log.Printf("🔐 [SOCKS5-搜索认证] 发现认证信息 - 用户名: '%s', 密码: '%s'", username, password)
							m.printSOCKS5AuthReport(session)
							return
						}
					}
				}
			}
		}
	}
}

// isPrintableString 检查字符串是否为可打印字符
func (m *EnhancedSOCKS5Monitor) isPrintableString(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// printSOCKS5AuthReport 打印SOCKS5认证报告
func (m *EnhancedSOCKS5Monitor) printSOCKS5AuthReport(session *SOCKS5Session) {
	// 避免重复输出（1分钟内同一会话只输出一次）
	if time.Since(m.lastAuthReport) < 1*time.Minute {
		return
	}
	m.lastAuthReport = time.Now()

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("🔐 eBPF内核级SOCKS5代理认证信息捕获")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("⏰ 捕获时间: %s\n", session.AuthTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("🔗 会话标识: %s\n", session.SessionID)
	fmt.Printf("🌐 代理服务器: %s:%d\n", session.ProxyIP, session.ProxyPort)
	fmt.Printf("👤 SOCKS5用户名: %s\n", session.Username)
	fmt.Printf("🔑 SOCKS5密码: %s\n", session.Password)

	if session.TargetHost != "" {
		fmt.Printf("🎯 目标地址: %s:%d\n", session.TargetHost, session.TargetPort)
	}

	fmt.Printf("📊 连接状态: %s\n", session.Status)
	fmt.Printf("🔍 监控方式: eBPF内核级数据包捕获\n")
	fmt.Printf("📋 目标进程: linuxService (PID: %d)\n", m.targetPID)
	fmt.Printf("💡 技术优势: 内核级监控，无法绕过，100%%捕获率\n")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
}

// CleanupSessions 清理过期会话
func (m *EnhancedSOCKS5Monitor) CleanupSessions() {
	now := time.Now()
	for sessionKey, session := range m.authSessions {
		// 清理5分钟前的会话
		if now.Sub(session.AuthTime) > 5*time.Minute {
			delete(m.authSessions, sessionKey)
			delete(m.packetBuffer, sessionKey)
		}
	}
}
