# eBPF网络编程深度指南

## 概述
eBPF (Extended Berkeley Packet Filter) 是Linux内核的一项革命性技术，允许在内核中运行安全的用户定义程序。本文基于Linux 6.17内核源代码，详细介绍eBPF在网络编程中的应用，包括包过滤、性能监控和高级网络功能。

## 1. eBPF基础概念

### 1.1 eBPF架构概述

eBPF是一种在内核中运行沙箱程序的技术，具有以下特点：

- **安全性**：通过验证器确保程序安全
- **高效性**：JIT编译提供接近原生性能
- **灵活性**：支持多种钩子和程序类型
- **可观测性**：提供丰富的内核观测能力

### 1.2 eBPF程序类型

```c
// include/uapi/linux/bpf.h
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,                  // 未指定类型
    BPF_PROG_TYPE_SOCKET_FILTER,           // 套接字过滤器
    BPF_PROG_TYPE_KPROBE,                  // Kprobe程序
    BPF_PROG_TYPE_SCHED_CLS,               // 流量控制分类器
    BPF_PROG_TYPE_SCHED_ACT,               // 流量控制动作
    BPF_PROG_TYPE_TRACEPOINT,              // 跟踪点
    BPF_PROG_TYPE_XDP,                      // XDP程序
    BPF_PROG_TYPE_PERF_EVENT,              // 性能事件
    BPF_PROG_TYPE_CGROUP_SKB,              // CGroup SKB程序
    BPF_PROG_TYPE_CGROUP_SOCK,              // CGroup套接字程序
    BPF_PROG_TYPE_LWT_IN,                  // 轻量级隧道输入
    BPF_PROG_TYPE_LWT_OUT,                 // 轻量级隧道输出
    BPF_PROG_TYPE_LWT_XMIT,                // 轻量级隧道发送
    BPF_PROG_TYPE_SOCK_OPS,                // 套接字操作
    BPF_PROG_TYPE_SK_SKB,                   // 套接字SKB程序
    BPF_PROG_TYPE_CGROUP_DEVICE,           // CGroup设备程序
    BPF_PROG_TYPE_SK_MSG,                   // 套接字消息程序
    BPF_PROG_TYPE_RAW_TRACEPOINT,          // 原始跟踪点
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,        // CGroup套接字地址
    BPF_PROG_TYPE_LWT_SEG6LOCAL,           // 轻量级隧道段6本地
    BPF_PROG_TYPE_LIRC_MODE2,              // LIRC模式2
    BPF_PROG_TYPE_SK_REUSEPORT,            // 套接字重用端口
    BPF_PROG_TYPE_FLOW_DISSECTOR,          // 流解析器
    BPF_PROG_TYPE_CGROUP_SYSCTL,           // CGroup系统控制
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, // 可写原始跟踪点
    BPF_PROG_TYPE_CGROUP_SOCKOPT,          // CGroup套接字选项
    BPF_PROG_TYPE_TRACING,                 // 跟踪程序
    BPF_PROG_TYPE_STRUCT_OPS,               // 结构操作
    BPF_PROG_TYPE_EXT,                     // 扩展程序
    BPF_PROG_TYPE_LSM,                     // Linux安全模块
    BPF_PROG_TYPE_SK_LOOKUP,                // 套接字查找
};
```

## 2. eBPF网络程序架构

### 2.1 eBPF程序结构

```c
// eBPF程序基本结构
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// 定义辅助函数
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    int action = XDP_PASS;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    // 处理IPv4数据包
    if (eth->h_proto == htons(ETH_P_IP)) {
        ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_DROP;

        // 处理TCP数据包
        if (ip->protocol == IPPROTO_TCP) {
            action = handle_tcp_packet(ctx, ip);
        }
    }

    return action;
}

// TCP数据包处理函数
static inline int handle_tcp_packet(struct xdp_md *ctx, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
    void *data_end = (void *)(long)ctx->data_end;

    // 检查TCP头部
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // 阻止特定端口的访问
    if (tcp->dest == htons(22)) {  // SSH端口
        return XDP_DROP;
    }

    return XDP_PASS;
}

// 许可证和版本
char _license[] SEC("license") = "GPL";
```

### 2.2 eBPF映射(Map)操作

```c
// 定义eBPF映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats SEC(".maps");

// 统计信息结构
struct stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
};

SEC("xdp")
int xdp_stats(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 key = 0;
    __u64 *count;
    struct stats *stats;
    __u64 bytes;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    // 计算数据包大小
    bytes = data_end - data;

    // 更新数据包计数
    count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // 更新统计信息
    stats = bpf_map_lookup_elem(&stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }

    return XDP_PASS;
}
```

## 3. XDP程序开发

### 3.1 XDP基础程序

```c
// XDP数据包过滤
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 ip_src, ip_dst;
    __u16 sport, dport;

    // 检查以太网头部
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // 只处理IPv4数据包
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // 提取IP地址
    ip_src = ip->saddr;
    ip_dst = ip->daddr;

    // 处理TCP数据包
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        sport = tcp->source;
        dport = tcp->dest;

        // 防火墙规则
        if (should_block_packet(ip_src, ip_dst, sport, dport)) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

// 数据包阻塞判断函数
static inline int should_block_packet(__u32 ip_src, __u32 ip_dst,
                                      __u16 sport, __u16 dport) {
    // 阻止访问SSH端口
    if (dport == htons(22))
        return 1;

    // 阻止来自特定IP的数据包
    if (ip_src == 0xC0A80101)  // 192.168.1.1
        return 1;

    // 阻止端口扫描
    if (sport < 1024 && dport < 1024)
        return 1;

    return 0;
}
```

### 3.2 XDP高级功能

```c
// XDP数据包重定向
SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 ifindex;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // 根据数据包类型选择目标接口
    if (eth->h_proto == htons(ETH_P_IP)) {
        ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        // 根据目标IP重定向
        ifindex = get_redirect_ifindex(ip->daddr);
        if (ifindex) {
            return bpf_redirect(ifindex, 0);
        }
    }

    return XDP_PASS;
}

// 获取重定向接口索引
static inline __u32 get_redirect_ifindex(__u32 daddr) {
    // 简单的路由表示例
    if ((daddr & 0xFFFFFF00) == 0xC0A80100)  // 192.168.1.0/24
        return 2;  // 接口索引2
    if ((daddr & 0xFFFF0000) == 0xC0A80000)  // 192.168.0.0/16
        return 3;  // 接口索引3

    return 0;  // 默认接口
}

// XDP数据包修改
SEC("xdp")
int xdp_nat(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // 处理TCP数据包
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        // NAT转换示例
        if (tcp->dest == htons(8080)) {  // 外部端口8080
            tcp->dest = htons(80);       // 内部端口80
            ip->daddr = 0x0100007F;       // 127.0.0.1
            // 重新计算校验和
            tcp->check = 0;
            ip->check = 0;
            tcp->check = tcp_v4_check(tcp, sizeof(*tcp), ip->saddr, ip->daddr);
            ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);
        }
    }

    return XDP_PASS;
}
```

## 4. TC (Traffic Control) 程序

### 4.1 TC分类器程序

```c
// TC分类器程序
SEC("classifier")
int tc_classifier(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 classid = 1;  // 默认类别

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // 基于协议类型分类
    switch (ip->protocol) {
    case IPPROTO_TCP:
        classid = 2;
        break;
    case IPPROTO_UDP:
        classid = 3;
        break;
    case IPPROTO_ICMP:
        classid = 4;
        break;
    }

    // 基于端口进一步分类
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;

        // HTTP流量
        if (tcp->dest == htons(80) || tcp->dest == htons(443))
            classid = 5;

        // SSH流量
        if (tcp->dest == htons(22))
            classid = 6;
    }

    // 设置数据包类别
    skb->tc_classid = classid;

    return TC_ACT_OK;
}
```

### 4.2 TC动作程序

```c
// TC动作程序
SEC("action")
int tc_action(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 mark = 0;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // 根据流量类型设置标记
    switch (ip->protocol) {
    case IPPROTO_TCP:
        mark = 0x1;
        break;
    case IPPROTO_UDP:
        mark = 0x2;
        break;
    case IPPROTO_ICMP:
        mark = 0x3;
        break;
    }

    // 设置数据包标记
    skb->mark = mark;

    return TC_ACT_OK;
}
```

## 5. 套接字过滤程序

### 5.1 套接字过滤器

```c
// 套接字过滤器
SEC("socket")
int socket_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return 0;

    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0;

    // 只接受TCP数据包
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return 0;

    // 只接受特定端口的数据包
    if (tcp->dest != htons(80) && tcp->dest != htons(443))
        return 0;

    return 1;  // 接受数据包
}
```

### 5.2 套接字操作程序

```c
// 套接字操作程序
SEC("sockops")
int sock_ops_prog(struct bpf_sock_ops *skops) {
    __u32 key = 0;
    __u64 *count;
    int op = (int) skops->op;

    // 更新操作计数
    count = bpf_map_lookup_elem(&sock_ops_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // 根据操作类型处理
    switch (op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // 处理被动连接建立
        handle_passive_established(skops);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        // 处理主动连接建立
        handle_active_established(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        // 处理状态变化
        handle_state_change(skops);
        break;
    }

    return 0;
}

// 处理被动连接建立
static inline void handle_passive_established(struct bpf_sock_ops *skops) {
    struct sockaddr_in addr;
    int family = skops->family;

    if (family == AF_INET) {
        // 获取远程地址
        bpf_getsockopt(skops, SOL_TCP, TCP_INFO, &addr, sizeof(addr));

        // 记录连接信息
        record_connection(skops->remote_ip4, skops->local_ip4,
                         skops->remote_port, skops->local_port);
    }
}
```

## 6. 高级网络功能

### 6.1 负载均衡

```c
// 负载均衡程序
SEC("xdp")
int xdp_load_balance(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 client_ip;
    __u16 client_port;
    __u32 server_ip;
    __u32 ifindex;
    __u32 hash;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // 处理TCP数据包
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        // 计算负载均衡哈希
        client_ip = ip->saddr;
        client_port = tcp->source;
        hash = jhash_2words(client_ip, client_port, 0);

        // 选择后端服务器
        server_ip = select_backend_server(hash);
        if (server_ip) {
            // 修改目标IP
            ip->daddr = server_ip;

            // 重新计算校验和
            ip->check = 0;
            ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);

            // 选择发送接口
            ifindex = get_egress_ifindex(server_ip);
            if (ifindex) {
                return bpf_redirect(ifindex, 0);
            }
        }
    }

    return XDP_PASS;
}

// 选择后端服务器
static inline __u32 select_backend_server(__u32 hash) {
    __u32 backend_count = 4;
    __u32 backend_index = hash % backend_count;

    // 后端服务器列表
    __u32 backend_servers[] = {
        0xC0A80102,  // 192.168.1.2
        0xC0A80103,  // 192.168.1.3
        0xC0A80104,  // 192.168.1.4
        0xC0A80105,  // 192.168.1.5
    };

    return backend_servers[backend_index];
}
```

### 6.2 DDoS防护

```c
// DDoS防护程序
SEC("xdp")
int xdp_ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 src_ip;
    __u64 current_time;
    __u64 *last_time;
    __u64 *count;
    __u32 key;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    src_ip = ip->saddr;
    current_time = bpf_ktime_get_ns();

    // 检查源IP的连接频率
    if (is_rate_limited(src_ip, current_time)) {
        return XDP_DROP;
    }

    // 更新连接统计
    update_connection_stats(src_ip, current_time);

    return XDP_PASS;
}

// 检查是否超过速率限制
static inline int is_rate_limited(__u32 src_ip, __u64 current_time) {
    __u64 *last_time;
    __u64 *count;
    __u64 time_diff;
    __u64 rate_limit = 1000;  // 每秒1000个包

    // 获取上次连接时间
    last_time = bpf_map_lookup_elem(&ip_last_seen, &src_ip);
    if (!last_time)
        return 0;

    // 获取连接计数
    count = bpf_map_lookup_elem(&ip_count, &src_ip);
    if (!count)
        return 0;

    // 计算时间差
    time_diff = current_time - *last_time;
    if (time_diff < 1000000000) {  // 1秒内
        // 检查是否超过速率限制
        if (*count > rate_limit) {
            return 1;
        }
    } else {
        // 重置计数器
        *count = 0;
        *last_time = current_time;
    }

    return 0;
}

// 更新连接统计
static inline void update_connection_stats(__u32 src_ip, __u64 current_time) {
    __u64 *last_time;
    __u64 *count;

    // 更新时间戳
    bpf_map_update_elem(&ip_last_seen, &src_ip, &current_time, BPF_ANY);

    // 更新计数器
    count = bpf_map_lookup_elem(&ip_count, &src_ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&ip_count, &src_ip, &init_count, BPF_ANY);
    }
}
```

## 7. 程序加载和调试

### 7.1 用户空间加载程序

```c
// 用户空间加载程序示例
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

int load_xdp_program(const char *ifname, const char *prog_path) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, ifindex;
    int err;

    // 加载eBPF对象
    err = bpf_object__open_file(prog_path, NULL, &obj);
    if (err) {
        fprintf(stderr, "Failed to open eBPF object: %s\n", strerror(-err));
        return -1;
    }

    // 加载程序到内核
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load eBPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    // 查找程序
    prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return -1;
    }

    // 获取程序文件描述符
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        bpf_object__close(obj);
        return -1;
    }

    // 获取接口索引
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index\n");
        bpf_object__close(obj);
        return -1;
    }

    // 附加XDP程序到接口
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    printf("XDP program loaded successfully on interface %s\n", ifname);
    bpf_object__close(obj);

    return 0;
}
```

### 7.2 调试和监控

```c
// 读取映射数据的用户空间程序
void read_stats(const char *map_path) {
    int map_fd;
    __u32 key = 0;
    struct stats stats;
    int err;

    // 打开映射
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("Failed to open map");
        return;
    }

    // 读取统计信息
    err = bpf_map_lookup_elem(map_fd, &key, &stats);
    if (err) {
        perror("Failed to lookup map element");
        close(map_fd);
        return;
    }

    // 打印统计信息
    printf("Network Statistics:\n");
    printf("  RX Packets: %llu\n", stats.rx_packets);
    printf("  RX Bytes: %llu\n", stats.rx_bytes);
    printf("  TX Packets: %llu\n", stats.tx_packets);
    printf("  TX Bytes: %llu\n", stats.tx_bytes);

    close(map_fd);
}

// 读取数据包计数
void read_packet_count(const char *map_path) {
    int map_fd;
    __u32 key = 0;
    __u64 count;
    int err;

    // 打开映射
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("Failed to open map");
        return;
    }

    // 读取计数
    err = bpf_map_lookup_elem(map_fd, &key, &count);
    if (err) {
        perror("Failed to lookup map element");
        close(map_fd);
        return;
    }

    printf("Total packets processed: %llu\n", count);

    close(map_fd);
}
```

## 8. 性能优化和最佳实践

### 8.1 性能优化技巧

```c
// 使用内联函数减少调用开销
static __always_inline int check_tcp_packet(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // 检查数据包边界
    if (data + sizeof(*eth) > data_end)
        return 0;

    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return 0;

    return 1;
}

// 使用循环展开提高性能
#define UNROLL_LOOP 4
static __always_inline void process_packet_batch(struct xdp_md **ctx_batch, int count) {
    int i;

    for (i = 0; i < count; i += UNROLL_LOOP) {
        // 展开循环
        if (i < count) process_single_packet(ctx_batch[i]);
        if (i + 1 < count) process_single_packet(ctx_batch[i + 1]);
        if (i + 2 < count) process_single_packet(ctx_batch[i + 2]);
        if (i + 3 < count) process_single_packet(ctx_batch[i + 3]);
    }
}

// 使用批量处理提高效率
SEC("xdp")
int xdp_batch_processor(struct xdp_md *ctx) {
    // 批量处理数据包
    // 这里简化了实际的批量处理逻辑
    return process_single_packet(ctx);
}
```

### 8.2 错误处理和调试

```c
// 添加调试信息
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) \
    bpf_printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

// 安全的数据包处理
static __always_inline int safe_packet_access(struct xdp_md *ctx, int offset, int size) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 检查访问是否在数据包范围内
    if (data + offset + size > data_end) {
        DEBUG_PRINT("Packet access out of bounds: offset=%d, size=%d\n", offset, size);
        return 0;
    }

    return 1;
}

// 错误处理包装器
static __always_inline int handle_packet_safely(struct xdp_md *ctx) {
    int action = XDP_PASS;

    // 检查数据包有效性
    if (!safe_packet_access(ctx, 0, sizeof(struct ethhdr))) {
        DEBUG_PRINT("Invalid Ethernet header\n");
        return XDP_DROP;
    }

    // 处理数据包
    action = process_packet_data(ctx);

    // 记录错误
    if (action == XDP_DROP) {
        DEBUG_PRINT("Packet dropped\n");
    }

    return action;
}
```

## 9. 总结

eBPF网络编程提供了强大的网络处理能力：

1. **高性能**：XDP提供接近硬件级别的处理性能
2. **灵活性**：支持多种网络程序类型和钩子
3. **安全性**：通过验证器确保程序安全
4. **可观测性**：提供丰富的网络监控能力
5. **可编程性**：支持复杂的网络功能实现

通过深入理解eBPF技术和网络编程实践，开发者可以实现高效、灵活的网络解决方案，包括防火墙、负载均衡、DDoS防护等多种网络功能。

---

*本指南基于Linux 6.17内核源代码，涵盖了eBPF网络编程的核心技术和最佳实践。*