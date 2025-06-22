#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 兼容性定义
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE 1
#endif

// 容器内eBPF监控 - 专门用于容器内流量监控
// 编译标志：-D CONTAINER_MODE=1

// SOCKS5认证信息结构
struct socks5_auth_event {
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 username[64];
    __u8 password[64];
    __u8 username_len;
    __u8 password_len;
    __u64 timestamp;
};

// 定义eBPF映射 - 用于与用户空间通信
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} socks5_events SEC(".maps");

// 临时存储SOCKS5会话信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct socks5_auth_event));
} socks5_sessions SEC(".maps");

// 容器内网络流量监控 - TC (Traffic Control) 钩子
SEC("tc")
int container_traffic_monitor(struct __sk_buff *skb)
{
    // 解析以太网头
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // 只处理IP数据包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // 只处理TCP数据包
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // 解析TCP头
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    // 检查是否为SOCKS5端口
    __u16 dst_port = bpf_ntohs(tcp->dest);
    if (dst_port != 1080 && dst_port != 1081 && dst_port != 7890 && 
        dst_port != 7891 && dst_port != 8080 && dst_port != 8081)
        return TC_ACT_OK;
    
    // 获取TCP负载
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload >= data_end)
        return TC_ACT_OK;
    
    // 检查负载长度
    int payload_len = data_end - payload;
    if (payload_len < 3)
        return TC_ACT_OK;
    
    // 分析SOCKS5协议
    __u8 *data_ptr = (__u8 *)payload;
    
    // 检查SOCKS5用户名密码认证
    if (payload_len >= 3 && data_ptr[0] == 0x01) {
        // SOCKS5用户名密码认证格式：
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        
        __u8 username_len = data_ptr[1];
        if (username_len > 0 && username_len < 64 && payload_len >= 2 + username_len + 1) {
            __u8 password_len = data_ptr[2 + username_len];
            if (password_len > 0 && password_len < 64 && 
                payload_len >= 2 + username_len + 1 + password_len) {
                
                // 创建SOCKS5认证事件
                struct socks5_auth_event event = {};
                event.pid = bpf_get_current_pid_tgid() >> 32;
                event.src_ip = bpf_ntohl(ip->saddr);
                event.dst_ip = bpf_ntohl(ip->daddr);
                event.src_port = bpf_ntohs(tcp->source);
                event.dst_port = dst_port;
                event.username_len = username_len;
                event.password_len = password_len;
                event.timestamp = bpf_ktime_get_ns();
                
                // 复制用户名（安全检查）
                int i;
                for (i = 0; i < username_len && i < 63; i++) {
                    if ((void *)&data_ptr[2 + i + 1] > data_end)
                        break;
                    event.username[i] = data_ptr[2 + i];
                }
                event.username[i] = '\0';
                
                // 复制密码（安全检查）
                for (i = 0; i < password_len && i < 63; i++) {
                    if ((void *)&data_ptr[2 + username_len + 1 + i + 1] > data_end)
                        break;
                    event.password[i] = data_ptr[2 + username_len + 1 + i];
                }
                event.password[i] = '\0';
                
                // 发送事件到用户空间
                bpf_perf_event_output(skb, &socks5_events, BPF_F_CURRENT_CPU, 
                                    &event, sizeof(event));
                
                // 存储会话信息
                __u64 session_key = ((__u64)event.src_ip << 32) | 
                                   ((__u64)event.src_port << 16) | event.dst_port;
                bpf_map_update_elem(&socks5_sessions, &session_key, &event, BPF_ANY);
            }
        }
    }
    
    return TC_ACT_OK;
}

// 容器内Socket监控 - Socket Filter
SEC("socket")
int container_socket_monitor(struct __sk_buff *skb)
{
    return container_traffic_monitor(skb);
}

// 简化的容器内监控 - 移除复杂的XDP逻辑以提高兼容性

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE; 