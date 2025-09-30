# 网络架构设计深度分析

## 概述
Linux网络子系统采用分层架构设计，实现了完整的TCP/IP协议栈。本文基于Linux 6.17内核源代码，深度分析网络架构的设计原理和实现机制。

## 1. 网络子系统整体架构

### 1.1 分层架构设计

网络子系统采用经典的OSI分层模型，但进行了优化和合并：

```
应用层 (Application Layer)
    ↓
套接字层 (Socket Layer) - BSD Socket接口
    ↓
协议层 (Protocol Layer) - TCP/UDP/ICMP等协议
    ↓
网络层 (Network Layer) - IPv4/IPv6路由和转发
    ↓
数据链路层 (Data Link Layer) - Ethernet/PPP等
    ↓
设备驱动层 (Device Driver Layer) - 硬件抽象
```

### 1.2 核心组件关系图

```c
// 网络子系统核心组件关系
struct net {
    // 网络命名空间
    struct netns_core core;
    struct netns_ipv4 ipv4;
    struct netns_ipv6 ipv6;
    // ...
};

struct net_device {
    // 网络设备抽象
    struct net_device_ops *netdev_ops;
    struct Qdisc *qdisc;
    // ...
};

struct sock {
    // 套接字内核表示
    struct sock_common __sk_common;
    struct sk_buff_head sk_receive_queue;
    // ...
};
```

## 2. 关键数据结构深度分析

### 2.1 网络设备结构 (net_device)

```c
// include/linux/netdevice.h
struct net_device {
    char name[IFNAMSIZ];                      // 设备名称
    struct hlist_node name_hlist;           // 名称哈希表

    // 设备操作接口
    const struct net_device_ops *netdev_ops;
    const struct ethtool_ops *ethtool_ops;

    // 设备状态和标志
    unsigned long state;                    // 设备状态
    unsigned int flags;                     // 网络接口标志
    unsigned int priv_flags;                // 私有标志

    // 硬件地址
    unsigned char perm_addr[MAX_ADDR_LEN];  // 永久地址
    unsigned char addr[MAX_ADDR_LEN];       // 当前地址

    // 设备统计信息
    struct rtnl_link_stats64 stats;         // 64位统计信息

    // 协议相关
    struct list_head ptype_all;             // 所有协议类型
    struct list_head ptype_specific;        // 特定协议类型

    // 调度队列
    struct Qdisc *qdisc;                    // 排队规则
    struct Qdisc *qdisc_sleeping;           // 睡眠队列

    // NAPI相关
    struct list_head napi_list;             // NAPI轮询列表

    // 多队列支持
    unsigned int num_rx_queues;             // 接收队列数量
    unsigned int num_tx_queues;             // 发送队列数量
    struct net_device *_tx;                 // 发送队列数组

    // 网络命名空间
    struct net *nd_net;                     // 所属网络命名空间

    // 操作函数
    netdev_features_t features;             // 设备特性
    netdev_features_t hw_features;           // 硬件特性
    netdev_features_t wanted_features;      // 期望特性

    // 更多字段...
};
```

### 2.2 套接字缓冲区 (sk_buff)

```c
// include/linux/skbuff.h
struct sk_buff {
    /* These two members must be first. */
    struct sk_buff *next;                   // 下一个skb
    struct sk_buff *prev;                   // 前一个skb

    union {
        struct net_device *dev;             // 关联的网络设备
        unsigned long dev_scratch;          // 设备临时数据
    };

    /* 数据区域 */
    char *data;                             // 数据起始位置
    unsigned char *head;                    // 缓冲区头部
    unsigned char *end;                     // 缓冲区尾部

    /* 网络层协议 */
    __u16 protocol;                         // 协议类型
    __u16 transport_header;                 // 传输层头部偏移
    __u16 network_header;                   // 网络层头部偏移
    __u16 mac_header;                       // MAC层头部偏移

    /* 数据包信息 */
    __u32 len;                              // 数据包长度
    __u32 data_len;                         // 数据长度
    __u32 truesize;                         // 实际占用大小

    /* 套接字关联 */
    struct sock *sk;                        // 关联的套接字

    /* 时间戳 */
    ktime_t tstamp;                         // 时间戳

    /* 优先级和标记 */
    __u32 priority;                         // 优先级
    __u32 mark;                             // 数据包标记

    /* 路由信息 */
    dst_entry *dst;                         // 路由缓存条目

    /* 控制缓冲区 */
    char cb[48] __aligned(8);              // 控制缓冲区

    /* 网络命名空间 */
    possible_net_t _sk_refdst;              // 目标网络命名空间

    /* 更多字段... */
};
```

### 2.3 套接字结构 (socket & sock)

```c
// include/linux/net.h
struct socket {
    socket_state state;                     // 套接字状态
    short type;                             // 套接字类型
    unsigned long flags;                    // 标志位
    struct socket_wq *wq;                   // 等待队列
    struct file *file;                      // 关联的文件
    struct sock *sk;                        // 内核套接字
    const struct proto_ops *ops;            // 操作函数
    struct net *net;                        // 网络命名空间
};

// include/net/sock.h
struct sock {
    struct sock_common __sk_common;         // 通用套接字字段
    unsigned char sk_shutdown : 2,          // 关闭状态
                  sk_no_check_tx : 1,      // 不检查发送校验和
                  sk_no_check_rx : 1,      // 不检查接收校验和
                  sk_userlocks : 4;        // 用户锁标志

    unsigned char sk_protocol : 8;          // 协议类型
    unsigned short sk_type;                 // 套接字类型

    atomic_t sk_wmem_alloc;                // 发送缓冲区分配
    atomic_t sk_rmem_alloc;                // 接收缓冲区分配

    int sk_rcvbuf;                          // 接收缓冲区大小
    int sk_sndbuf;                          // 发送缓冲区大小

    /* 协议特定字段 */
    struct sk_buff *sk_receive_queue;       // 接收队列
    struct sk_buff *sk_write_queue;         // 发送队列
    struct sk_buff_head sk_error_queue;     // 错误队列

    /* 网络层字段 */
    struct dst_entry *sk_dst_cache;         // 路由缓存
    struct rtable *sk_route_caps;           // 路由能力

    /* 传输层字段 */
    __u32 sk_mark;                          // 数据包标记
    __u32 sk_priority;                     // 优先级

    /* 选项字段 */
    unsigned long sk_flags;                 // 套接字标志

    /* 协议操作 */
    const struct proto *sk_prot;            // 协议操作函数

    /* 更多字段... */
};
```

## 3. 网络协议栈实现

### 3.1 套接字层实现

```c
// net/socket.c
static const struct net_proto_family inet_family_ops = {
    .family = PF_INET,
    .create = inet_create,
    .owner  = THIS_MODULE,
};

int inet_create(struct net *net, struct socket *sock, int protocol,
                int kern)
{
    struct sock *sk;
    struct inet_sock *inet;
    struct proto *answer_prot;
    int err;

    // 根据套接字类型选择协议
    switch (sock->type) {
    case SOCK_STREAM:
        if (protocol && protocol != IPPROTO_TCP)
            return -EPROTONOSUPPORT;
        protocol = IPPROTO_TCP;
        answer_prot = &tcp_prot;
        break;
    case SOCK_DGRAM:
        if (protocol && protocol != IPPROTO_UDP)
            return -EPROTONOSUPPORT;
        protocol = IPPROTO_UDP;
        answer_prot = &udp_prot;
        break;
    // ... 其他协议
    }

    // 创建套接字
    sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
    if (!sk)
        return -ENOBUFS;

    // 初始化套接字
    sock_init_data(sock, sk);
    inet = inet_sk(sk);

    // 设置协议特定字段
    inet->inet_dport = 0;
    inet->inet_daddr = 0;
    inet->inet_sport = 0;
    inet->inet_saddr = 0;

    // 设置操作函数
    sock->ops = &inet_stream_ops;

    return 0;
}
```

### 3.2 网络层实现

```c
// net/ipv4/ip_output.c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct iphdr *iph;
    struct rtable *rt;
    struct net_device *dev;

    // 获取路由信息
    rt = skb_rtable(skb);
    dev = rt->dst.dev;

    // 设置IP头
    iph = ip_hdr(skb);
    iph->tot_len = htons(skb->len);
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    // 发送数据包
    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
                       net, sk, skb, NULL, dev,
                       ip_finish_output,
                       !(IPCB(skb)->flags & IPSKB_REROUTED));
}

static int ip_finish_output(struct net *net, struct sock *sk,
                          struct sk_buff *skb)
{
    struct rtable *rt = skb_rtable(skb);
    struct net_device *dev = rt->dst.dev;

    // 分片处理
    if (skb->len > dst_mtu(&rt->dst) && !skb_is_gso(skb))
        return ip_fragment(net, sk, skb, ip_finish_output2);

    return ip_finish_output2(net, sk, skb);
}
```

### 3.3 传输层实现

```c
// net/ipv4/tcp_output.c
int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
                     gfp_t gfp_mask)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
    struct tcphdr *th;
    int tcp_header_size = tcp_header_size_thin(sk);
    int err;

    // 设置TCP头
    th = (struct tcphdr *)skb_push(skb, tcp_header_size);
    skb_reset_transport_header(skb);

    // 填充TCP头字段
    th->source     = inet->inet_sport;
    th->dest       = inet->inet_dport;
    th->seq        = htonl(tcb->seq);
    th->ack_seq    = htonl(tp->rcv_nxt);
    th->doff       = tcp_header_size / 4;

    // 设置标志位
    if (tcb->flags & TCPHDR_FIN)
        th->fin = 1;
    if (tcb->flags & TCPHDR_SYN)
        th->syn = 1;
    if (tcb->flags & TCPHDR_RST)
        th->rst = 1;
    if (tcb->flags & TCPHDR_PSH)
        th->psh = 1;
    if (tcb->flags & TCPHDR_ACK)
        th->ack = 1;

    // 计算校验和
    th->check = 0;
    th->check = tcp_v4_check(skb->len, inet->inet_saddr,
                            inet->inet_daddr, skb);

    // 发送数据包
    err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);
    if (unlikely(err <= 0))
        return err;

    return 0;
}
```

## 4. 网络设备注册和管理

### 4.1 设备注册流程

```c
// net/core/dev.c
int register_netdevice(struct net_device *dev)
{
    struct net *net = dev_net(dev);
    int ret;

    // 初始化设备队列
    netdev_init_queues(dev);

    // 设置默认操作
    if (!dev->netdev_ops)
        dev->netdev_ops = &default_netdev_ops;

    // 分配设备索引
    ret = dev_new_index(net, dev);
    if (ret < 0)
        goto out;

    // 初始化设备特性
    dev_init_features(dev);

    // 添加到设备列表
    list_add_tail(&dev->dev_list, &net->dev_base_head);

    // 通知网络子系统
    rtmsg_ifinfo(RTM_NEWLINK, dev, ~0U, GFP_KERNEL);

    // 启用设备
    ret = call_netdevice_notifiers(NETDEV_REGISTER, dev);
    if (ret)
        goto err_uninit;

    return 0;

err_uninit:
    list_del(&dev->dev_list);
out:
    return ret;
}
```

### 4.2 设备操作接口

```c
// include/linux/netdevice.h
struct net_device_ops {
    int (*ndo_init)(struct net_device *dev);
    void (*ndo_uninit)(struct net_device *dev);
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
                                  struct net_device *dev);
    netdev_features_t (*ndo_features_check)(struct sk_buff *skb,
                                            struct net_device *dev,
                                            netdev_features_t features);
    u16 (*ndo_select_queue)(struct net_device *dev,
                            struct sk_buff *skb,
                            struct net_device *sb_dev);
    void (*ndo_change_rx_flags)(struct net_device *dev,
                               int flags);
    void (*ndo_set_rx_mode)(struct net_device *dev);
    int (*ndo_set_mac_address)(struct net_device *dev,
                               void *addr);
    int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);
    void (*ndo_tx_timeout)(struct net_device *dev);
    struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
                                                 struct rtnl_link_stats64 *storage);
    int (*ndo_do_ioctl)(struct net_device *dev,
                        struct ifreq *ifr, int cmd);
    int (*ndo_set_config)(struct net_device *dev,
                          struct ifmap *map);
    int (*ndo_change_carrier)(struct net_device *dev,
                              bool new_carrier);
    // 更多操作...
};
```

## 5. 网络命名空间实现

### 5.1 命名空间结构

```c
// include/net/net_namespace.h
struct net {
    refcount_t count;                       // 引用计数
    spinlock_t rules_mod_lock;             // 规则修改锁
    struct list_head list;                  // 命名空间列表
    struct list_head exit_list;             // 退出列表

    /* 网络设备 */
    struct net_device *loopback_dev;        // 回环设备
    struct list_head dev_base_head;         // 设备链表
    struct hlist_head *dev_name_head;       // 设备名称哈希
    struct hlist_head *dev_index_head;      // 设备索引哈希

    /* 协议栈 */
    struct netns_core core;                 // 核心协议栈
    struct netns_ipv4 ipv4;                 // IPv4协议栈
    struct netns_ipv6 ipv6;                 // IPv6协议栈
    struct netns_unix unx;                  // UNIX域协议栈
    struct netns_packet pkt;                // 数据包协议栈

    /* 路由 */
    struct fib_table *ipv4.fib_main;        // 主路由表
    struct fib_table *ipv4.fib_default;     // 默认路由表

    /* 防火墙 */
    struct xt_table *iptables;              // IPv4防火墙表
    struct xt_table *ip6tables;             // IPv6防火墙表

    /* 套接字 */
    struct net_generic *gen;                 // 通用数据

    /* 统计信息 */
    struct netns_frags frags;               // 分片统计

    /* 更多字段... */
};
```

### 5.2 命名空间操作

```c
// net/core/net_namespace.c
struct net *copy_net_ns(unsigned long flags,
                        struct user_namespace *user_ns,
                        struct net *old_net)
{
    struct net *net;
    int err;

    // 分配新的网络命名空间
    net = net_alloc();
    if (!net)
        return ERR_PTR(-ENOMEM);

    // 设置命名空间
    get_user_ns(user_ns);

    // 复制配置
    mutex_lock(&net_mutex);
    err = setup_net(net, user_ns);
    if (err) {
        mutex_unlock(&net_mutex);
        net_free(net);
        return ERR_PTR(err);
    }

    mutex_unlock(&net_mutex);

    return net;
}

static __net_init int setup_net(struct net *net, struct user_namespace *user_ns)
{
    const struct pernet_operations *ops;
    int error;

    // 初始化基础结构
    atomic_set(&net->count, 1);
    atomic_set(&net->passive, 1);
    net->user_ns = user_ns;

    // 初始化各个子系统
    list_for_each_entry(ops, &pernet_list, list) {
        if (ops->init) {
            error = ops->init(net);
            if (error < 0)
                goto out_undo;
        }
    }

    return 0;

out_undo:
    // 清理初始化失败的子系统
    list_for_each_entry_continue_reverse(ops, &pernet_list, list) {
        if (ops->exit)
            ops->exit(net);
    }

    return error;
}
```

## 6. 总结

Linux网络子系统的架构设计体现了以下特点：

1. **分层抽象**：清晰的分层设计，每层都有明确的职责
2. **模块化**：各协议和设备相对独立，便于扩展和维护
3. **高性能**：通过零拷贝、DMA等技术优化性能
4. **可扩展**：支持新的协议和设备类型
5. **安全性**：通过命名空间和防火墙提供安全隔离

理解网络架构设计对于深入掌握Linux网络子系统至关重要，这为后续的性能优化和驱动开发奠定了基础。

---

*本分析基于Linux 6.17内核源代码，涵盖了网络架构设计的核心内容。*