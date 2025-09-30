# 网络驱动开发深度指南

## 概述
网络驱动开发是Linux内核开发的重要组成部分。本文基于Linux 6.17内核源代码，详细介绍网络驱动开发框架、实现机制和最佳实践，帮助开发者掌握网络驱动开发技术。

## 1. 网络驱动框架概述

### 1.1 驱动架构设计

Linux网络驱动采用分层架构设计，主要包括：

```
应用层
    ↓
套接字层 (Socket API)
    ↓
协议层 (TCP/IP Protocol Stack)
    ↓
网络设备接口层 (Net Device Interface)
    ↓
设备驱动层 (Device Driver)
    ↓
硬件层 (Hardware)
```

### 1.2 驱动开发流程

1. **设备初始化**：分配和初始化net_device结构
2. **设备注册**：向内核注册网络设备
3. **中断处理**：配置和注册中断处理函数
4. **数据收发**：实现数据包收发功能
5. **设备管理**：实现设备状态管理
6. **设备卸载**：清理资源和注销设备

## 2. 网络设备结构

### 2.1 net_device结构详解

```c
// include/linux/netdevice.h
struct net_device {
    /* 基本设备信息 */
    char name[IFNAMSIZ];                      // 设备名称
    struct hlist_node name_hlist;           // 名称哈希表节点

    /* 设备操作接口 */
    const struct net_device_ops *netdev_ops; // 设备操作函数表
    const struct ethtool_ops *ethtool_ops;   // ethtool操作函数表

    /* 设备状态 */
    unsigned long state;                    // 设备状态
    unsigned int flags;                     // 网络接口标志
    unsigned int priv_flags;                // 私有标志

    /* 硬件信息 */
    unsigned char perm_addr[MAX_ADDR_LEN];  // 永久MAC地址
    unsigned char addr[MAX_ADDR_LEN];       // 当前MAC地址
    unsigned char broadcast[MAX_ADDR_LEN];  // 广播地址

    /* 设备统计 */
    struct rtnl_link_stats64 stats;         // 64位统计信息

    /* 传输参数 */
    unsigned int mtu;                       // 最大传输单元
    unsigned short type;                    // 接口类型
    unsigned short hard_header_len;         // 硬件头部长度

    /* 队列管理 */
    struct net_device *_tx;                 // 发送队列数组
    struct net_device *_rx;                 // 接收队列数组
    unsigned int num_tx_queues;             // 发送队列数量
    unsigned int num_rx_queues;             // 接收队列数量

    /* NAPI支持 */
    struct list_head napi_list;             // NAPI轮询列表

    /* 协议相关 */
    struct list_head ptype_all;             // 所有协议类型
    struct list_head ptype_specific;        // 特定协议类型

    /* 特性标志 */
    netdev_features_t features;             // 设备特性
    netdev_features_t hw_features;           // 硬件特性
    netdev_features_t wanted_features;      // 期望特性

    /* 网络命名空间 */
    struct net *nd_net;                     // 网络命名空间

    /* 设备私有数据 */
    void *priv;                             // 驱动私有数据

    /* 中断信息 */
    int irq;                                // 中断号

    /* DMA信息 */
    dma_addr_t dma_mask;                    // DMA掩码

    /* 更多字段... */
};
```

### 2.2 net_device_ops操作接口

```c
// include/linux/netdevice.h
struct net_device_ops {
    /* 设备生命周期管理 */
    int (*ndo_init)(struct net_device *dev);
    void (*ndo_uninit)(struct net_device *dev);
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);

    /* 数据包传输 */
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
                                  struct net_device *dev);

    /* 设备特性检查 */
    netdev_features_t (*ndo_features_check)(struct sk_buff *skb,
                                            struct net_device *dev,
                                            netdev_features_t features);

    /* 队列选择 */
    u16 (*ndo_select_queue)(struct net_device *dev,
                            struct sk_buff *skb,
                            struct net_device *sb_dev);

    /* 地址配置 */
    int (*ndo_set_mac_address)(struct net_device *dev,
                               void *addr);
    int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);

    /* 多播配置 */
    void (*ndo_set_rx_mode)(struct net_device *dev);

    /* 统计信息 */
    struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
                                                 struct rtnl_link_stats64 *storage);

    /* 超时处理 */
    void (*ndo_tx_timeout)(struct net_device *dev);

    /* VLAN支持 */
    int (*ndo_vlan_rx_add_vid)(struct net_device *dev,
                              __be16 proto, u16 vid);
    int (*ndo_vlan_rx_kill_vid)(struct net_device *dev,
                               __be16 proto, u16 vid);

    /* 更多操作... */
};
```

## 3. 驱动开发基础实现

### 3.1 驱动初始化和注册

```c
// 驱动初始化函数
static int __init my_net_driver_init(void)
{
    int ret;

    printk(KERN_INFO "My Network Driver v1.0\n");

    // 注册平台设备
    ret = platform_driver_register(&my_platform_driver);
    if (ret) {
        printk(KERN_ERR "Failed to register platform driver\n");
        return ret;
    }

    return 0;
}

// 平台驱动结构
static struct platform_driver my_platform_driver = {
    .probe = my_net_probe,
    .remove = my_net_remove,
    .driver = {
        .name = "my-net-device",
        .owner = THIS_MODULE,
    },
};

// 设备探测函数
static int my_net_probe(struct platform_device *pdev)
{
    struct net_device *dev;
    struct my_net_priv *priv;
    int ret;

    // 分配网络设备
    dev = alloc_etherdev(sizeof(struct my_net_priv));
    if (!dev) {
        dev_err(&pdev->dev, "Failed to allocate net device\n");
        return -ENOMEM;
    }

    // 设置平台设备数据
    platform_set_drvdata(pdev, dev);
    SET_NETDEV_DEV(dev, &pdev->dev);

    // 获取私有数据
    priv = netdev_priv(dev);
    priv->dev = dev;
    priv->pdev = pdev;

    // 初始化设备操作
    dev->netdev_ops = &my_netdev_ops;
    dev->ethtool_ops = &my_ethtool_ops;

    // 设置设备特性
    dev->features |= NETIF_F_HIGHDMA;
    dev->features |= NETIF_F_NETNS_LOCAL;

    // 设置MAC地址
    my_net_get_mac_address(dev);

    // 注册网络设备
    ret = register_netdev(dev);
    if (ret) {
        dev_err(&pdev->dev, "Failed to register net device\n");
        free_netdev(dev);
        return ret;
    }

    printk(KERN_INFO "Network device %s registered\n", dev->name);

    return 0;
}

// 设备移除函数
static int my_net_remove(struct platform_device *pdev)
{
    struct net_device *dev = platform_get_drvdata(pdev);

    if (dev) {
        // 注销网络设备
        unregister_netdev(dev);
        // 释放设备
        free_netdev(dev);
    }

    printk(KERN_INFO "Network device removed\n");

    return 0;
}
```

### 3.2 设备打开和关闭

```c
// 设备打开函数
static int my_net_open(struct net_device *dev)
{
    struct my_net_priv *priv = netdev_priv(dev);
    int ret;

    // 申请IRQ
    ret = request_irq(dev->irq, my_net_interrupt,
                     IRQF_SHARED, dev->name, dev);
    if (ret) {
        dev_err(&dev->dev, "Failed to request IRQ %d\n", dev->irq);
        return ret;
    }

    // 初始化NAPI
    netif_napi_add(dev, &priv->napi, my_net_poll, NAPI_POLL_WEIGHT);
    napi_enable(&priv->napi);

    // 初始化硬件
    my_net_hardware_init(dev);

    // 启用网络队列
    netif_start_queue(dev);

    // 更新设备状态
    netif_carrier_on(dev);

    printk(KERN_INFO "Network device %s opened\n", dev->name);

    return 0;
}

// 设备关闭函数
static int my_net_stop(struct net_device *dev)
{
    struct my_net_priv *priv = netdev_priv(dev);

    // 停止网络队列
    netif_stop_queue(dev);

    // 关闭载波
    netif_carrier_off(dev);

    // 禁用NAPI
    napi_disable(&priv->napi);

    // 释放IRQ
    free_irq(dev->irq, dev);

    // 停止硬件
    my_net_hardware_stop(dev);

    printk(KERN_INFO "Network device %s stopped\n", dev->name);

    return 0;
}
```

## 4. 数据包传输实现

### 4.1 发送数据包

```c
// 发送数据包函数
static netdev_tx_t my_net_start_xmit(struct sk_buff *skb,
                                     struct net_device *dev)
{
    struct my_net_priv *priv = netdev_priv(dev);
    struct my_net_desc *desc;
    dma_addr_t dma_addr;
    int tx_head;

    // 检查发送队列是否已满
    if (my_net_tx_queue_full(priv)) {
        netif_stop_queue(dev);
        return NETDEV_TX_BUSY;
    }

    // 获取发送描述符
    tx_head = priv->tx_head;
    desc = &priv->tx_desc[tx_head];

    // 设置DMA映射
    dma_addr = dma_map_single(&dev->dev, skb->data, skb->len,
                              DMA_TO_DEVICE);
    if (dma_mapping_error(&dev->dev, dma_addr)) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    // 设置发送描述符
    desc->addr = dma_addr;
    desc->len = skb->len;
    desc->flags = MY_NET_DESC_FLAG_OWN | MY_NET_DESC_FLAG_EOP;

    // 保存SKB信息
    priv->tx_skb[tx_head] = skb;
    priv->tx_dma[tx_head] = dma_addr;

    // 更新发送头指针
    priv->tx_head = (tx_head + 1) % MY_NET_TX_DESC_NUM;

    // 启动发送
    my_net_start_transmission(priv);

    // 更新统计信息
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    // 检查发送队列空间
    if (my_net_tx_queue_space(priv) < MY_NET_TX_WAKEUP_THRESH) {
        netif_stop_queue(dev);
    }

    return NETDEV_TX_OK;
}

// 发送完成中断处理
static void my_net_tx_complete(struct my_net_priv *priv)
{
    struct net_device *dev = priv->dev;
    int tx_tail = priv->tx_tail;

    // 处理已完成的发送描述符
    while (tx_tail != priv->tx_head) {
        struct my_net_desc *desc = &priv->tx_desc[tx_tail];

        // 检查描述符是否已释放
        if (desc->flags & MY_NET_DESC_FLAG_OWN) {
            break;
        }

        // 释放DMA映射
        dma_unmap_single(&dev->dev, priv->tx_dma[tx_tail],
                        priv->tx_skb[tx_tail]->len, DMA_TO_DEVICE);

        // 释放SKB
        dev_kfree_skb(priv->tx_skb[tx_tail]);
        priv->tx_skb[tx_tail] = NULL;

        // 更新尾指针
        tx_tail = (tx_tail + 1) % MY_NET_TX_DESC_NUM;
    }

    // 更新尾指针
    priv->tx_tail = tx_tail;

    // 如果发送队列有空间，重新启动
    if (netif_queue_stopped(dev) &&
        my_net_tx_queue_space(priv) > MY_NET_TX_WAKEUP_THRESH) {
        netif_wake_queue(dev);
    }
}
```

### 4.2 接收数据包

```c
// NAPI轮询函数
static int my_net_poll(struct napi_struct *napi, int budget)
{
    struct my_net_priv *priv = container_of(napi, struct my_net_priv, napi);
    struct net_device *dev = priv->dev;
    int work_done = 0;

    // 处理接收描述符
    while (work_done < budget) {
        struct sk_buff *skb;
        struct my_net_desc *desc;
        dma_addr_t dma_addr;
        int rx_head;

        // 检查是否有新数据包
        if (!my_net_rx_desc_ready(priv)) {
            break;
        }

        // 获取接收描述符
        rx_head = priv->rx_head;
        desc = &priv->rx_desc[rx_head];

        // 分配SKB
        skb = netdev_alloc_skb(dev, desc->len + NET_IP_ALIGN);
        if (!skb) {
            dev->stats.rx_dropped++;
            break;
        }

        // 对齐数据
        skb_reserve(skb, NET_IP_ALIGN);

        // 设置DMA映射
        dma_addr = dma_map_single(&dev->dev, skb->data, desc->len,
                                  DMA_FROM_DEVICE);
        if (dma_mapping_error(&dev->dev, dma_addr)) {
            dev_kfree_skb(skb);
            dev->stats.rx_dropped++;
            break;
        }

        // 复制数据到SKB
        skb_copy_to_linear_data(skb, priv->rx_buf[rx_head], desc->len);
        skb_put(skb, desc->len);

        // 设置网络头
        skb->protocol = eth_type_trans(skb, dev);

        // 设置校验和信息
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        // 传递给网络栈
        netif_receive_skb(skb);

        // 更新统计信息
        dev->stats.rx_packets++;
        dev->stats.rx_bytes += desc->len;

        // 重新使用描述符
        my_net_reuse_rx_desc(priv, rx_head);

        // 更新头指针
        priv->rx_head = (rx_head + 1) % MY_NET_RX_DESC_NUM;

        work_done++;
    }

    // 如果预算用完，继续轮询
    if (work_done == budget) {
        return budget;
    }

    // 完成轮询，重新启用中断
    napi_complete_done(napi, work_done);
    my_net_enable_rx_interrupt(priv);

    return work_done;
}

// 接收中断处理
static irqreturn_t my_net_interrupt(int irq, void *dev_id)
{
    struct net_device *dev = (struct net_device *)dev_id;
    struct my_net_priv *priv = netdev_priv(dev);
    u32 status;

    // 读取中断状态
    status = my_net_read_irq_status(priv);

    // 清除中断状态
    my_net_clear_irq_status(priv, status);

    // 处理接收中断
    if (status & MY_NET_IRQ_RX) {
        // 禁用接收中断，启用NAPI
        my_net_disable_rx_interrupt(priv);
        napi_schedule(&priv->napi);
    }

    // 处理发送完成中断
    if (status & MY_NET_IRQ_TX) {
        my_net_tx_complete(priv);
    }

    return IRQ_HANDLED;
}
```

## 5. 硬件初始化和管理

### 5.1 硬件初始化

```c
// 硬件初始化函数
static void my_net_hardware_init(struct net_device *dev)
{
    struct my_net_priv *priv = netdev_priv(dev);

    // 重置硬件
    my_net_reset_hardware(priv);

    // 初始化发送队列
    my_net_init_tx_queue(priv);

    // 初始化接收队列
    my_net_init_rx_queue(priv);

    // 设置MAC地址
    my_net_set_mac_address(priv, dev->dev_addr);

    // 配置中断
    my_net_configure_interrupts(priv);

    // 启用接收和发送
    my_net_enable_rx_tx(priv);

    // 设置MTU
    my_net_set_mtu(priv, dev->mtu);
}

// 初始化发送队列
static void my_net_init_tx_queue(struct my_net_priv *priv)
{
    int i;

    // 分配发送描述符
    priv->tx_desc = dma_alloc_coherent(&priv->dev->dev,
                                        sizeof(struct my_net_desc) * MY_NET_TX_DESC_NUM,
                                        &priv->tx_desc_dma, GFP_KERNEL);

    // 分配发送缓冲区
    priv->tx_skb = kzalloc(sizeof(struct sk_buff *) * MY_NET_TX_DESC_NUM, GFP_KERNEL);
    priv->tx_dma = kzalloc(sizeof(dma_addr_t) * MY_NET_TX_DESC_NUM, GFP_KERNEL);

    // 初始化描述符
    for (i = 0; i < MY_NET_TX_DESC_NUM; i++) {
        priv->tx_desc[i].flags = 0;
        priv->tx_skb[i] = NULL;
        priv->tx_dma[i] = 0;
    }

    // 重置队列指针
    priv->tx_head = 0;
    priv->tx_tail = 0;
}

// 初始化接收队列
static void my_net_init_rx_queue(struct my_net_priv *priv)
{
    int i;

    // 分配接收描述符
    priv->rx_desc = dma_alloc_coherent(&priv->dev->dev,
                                        sizeof(struct my_net_desc) * MY_NET_RX_DESC_NUM,
                                        &priv->rx_desc_dma, GFP_KERNEL);

    // 分配接收缓冲区
    priv->rx_buf = kzalloc(sizeof(void *) * MY_NET_RX_DESC_NUM, GFP_KERNEL);
    priv->rx_dma = kzalloc(sizeof(dma_addr_t) * MY_NET_RX_DESC_NUM, GFP_KERNEL);

    // 初始化描述符和缓冲区
    for (i = 0; i < MY_NET_RX_DESC_NUM; i++) {
        // 分配接收缓冲区
        priv->rx_buf[i] = kmalloc(MY_NET_RX_BUF_SIZE, GFP_KERNEL);

        // 设置DMA映射
        priv->rx_dma[i] = dma_map_single(&priv->dev->dev, priv->rx_buf[i],
                                        MY_NET_RX_BUF_SIZE, DMA_FROM_DEVICE);

        // 设置描述符
        priv->rx_desc[i].addr = priv->rx_dma[i];
        priv->rx_desc[i].len = MY_NET_RX_BUF_SIZE;
        priv->rx_desc[i].flags = MY_NET_DESC_FLAG_OWN;
    }

    // 重置队列指针
    priv->rx_head = 0;
}
```

### 5.2 硬件停止和清理

```c
// 硬件停止函数
static void my_net_hardware_stop(struct net_device *dev)
{
    struct my_net_priv *priv = netdev_priv(dev);

    // 停止发送和接收
    my_net_disable_rx_tx(priv);

    // 重置硬件
    my_net_reset_hardware(priv);

    // 释放发送队列
    my_net_free_tx_queue(priv);

    // 释放接收队列
    my_net_free_rx_queue(priv);
}

// 释放发送队列
static void my_net_free_tx_queue(struct my_net_priv *priv)
{
    int i;

    // 释放发送描述符
    if (priv->tx_desc) {
        dma_free_coherent(&priv->dev->dev,
                          sizeof(struct my_net_desc) * MY_NET_TX_DESC_NUM,
                          priv->tx_desc, priv->tx_desc_dma);
        priv->tx_desc = NULL;
    }

    // 释放发送缓冲区
    if (priv->tx_skb) {
        for (i = 0; i < MY_NET_TX_DESC_NUM; i++) {
            if (priv->tx_skb[i]) {
                dev_kfree_skb(priv->tx_skb[i]);
                priv->tx_skb[i] = NULL;
            }
        }
        kfree(priv->tx_skb);
        priv->tx_skb = NULL;
    }

    kfree(priv->tx_dma);
    priv->tx_dma = NULL;
}

// 释放接收队列
static void my_net_free_rx_queue(struct my_net_priv *priv)
{
    int i;

    // 释放接收描述符
    if (priv->rx_desc) {
        dma_free_coherent(&priv->dev->dev,
                          sizeof(struct my_net_desc) * MY_NET_RX_DESC_NUM,
                          priv->rx_desc, priv->rx_desc_dma);
        priv->rx_desc = NULL;
    }

    // 释放接收缓冲区
    if (priv->rx_buf) {
        for (i = 0; i < MY_NET_RX_DESC_NUM; i++) {
            if (priv->rx_buf[i]) {
                dma_unmap_single(&priv->dev->dev, priv->rx_dma[i],
                                MY_NET_RX_BUF_SIZE, DMA_FROM_DEVICE);
                kfree(priv->rx_buf[i]);
                priv->rx_buf[i] = NULL;
            }
        }
        kfree(priv->rx_buf);
        priv->rx_buf = NULL;
    }

    kfree(priv->rx_dma);
    priv->rx_dma = NULL;
}
```

## 6. 统计信息和调试

### 6.1 统计信息收集

```c
// 获取统计信息
static struct rtnl_link_stats64 *my_net_get_stats64(
    struct net_device *dev,
    struct rtnl_link_stats64 *stats)
{
    struct my_net_priv *priv = netdev_priv(dev);
    unsigned int start;

    // 原子读取统计信息
    do {
        start = u64_stats_fetch_begin(&priv->syncp);
        *stats = priv->stats;
    } while (u64_stats_fetch_retry(&priv->syncp, start));

    // 添加硬件统计信息
    my_net_get_hw_stats(priv, stats);

    return stats;
}

// ethtool统计信息
static void my_net_get_ethtool_stats(struct net_device *dev,
                                    struct ethtool_stats *stats,
                                    u64 *data)
{
    struct my_net_priv *priv = netdev_priv(dev);
    int i;

    // 收集统计信息
    for (i = 0; i < MY_NET_STATS_LEN; i++) {
        switch (i) {
        case 0:
            data[i] = priv->stats.rx_packets;
            break;
        case 1:
            data[i] = priv->stats.rx_bytes;
            break;
        case 2:
            data[i] = priv->stats.tx_packets;
            break;
        case 3:
            data[i] = priv->stats.tx_bytes;
            break;
        case 4:
            data[i] = priv->stats.rx_errors;
            break;
        case 5:
            data[i] = priv->stats.tx_errors;
            break;
        case 6:
            data[i] = priv->stats.rx_dropped;
            break;
        case 7:
            data[i] = priv->stats.tx_dropped;
            break;
        // 更多统计项...
        }
    }
}

// 统计信息字符串
static const char my_net_stats_strings[][ETH_GSTRING_LEN] = {
    "rx_packets", "rx_bytes", "tx_packets", "tx_bytes",
    "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
    "rx_missed_errors", "tx_aborted_errors",
    "rx_length_errors", "rx_crc_errors",
};
```

### 6.2 调试功能

```c
// 调试信息输出
static void my_net_dump_regs(struct my_net_priv *priv)
{
    struct net_device *dev = priv->dev;

    dev_dbg(&dev->dev, "=== Register Dump ===\n");
    dev_dbg(&dev->dev, "CTRL:  0x%08x\n", my_net_read_reg(priv, MY_NET_REG_CTRL));
    dev_dbg(&dev->dev, "STATUS: 0x%08x\n", my_net_read_reg(priv, MY_NET_REG_STATUS));
    dev_dbg(&dev->dev, "TX_CFG: 0x%08x\n", my_net_read_reg(priv, MY_NET_REG_TX_CFG));
    dev_dbg(&dev->dev, "RX_CFG: 0x%08x\n", my_net_read_reg(priv, MY_NET_REG_RX_CFG));
    dev_dbg(&dev->dev, "IRQ_MASK: 0x%08x\n", my_net_read_reg(priv, MY_NET_REG_IRQ_MASK));
    dev_dbg(&dev->dev, "IRQ_STATUS: 0x%08x\n", my_net_read_reg(priv, MY_NET_REG_IRQ_STATUS));
}

// 调试文件系统
static int my_net_debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_net_debug_show, inode->i_private);
}

static int my_net_debug_show(struct seq_file *seq, void *v)
{
    struct my_net_priv *priv = seq->private;
    struct net_device *dev = priv->dev;

    seq_printf(seq, "Network Driver Debug Information\n");
    seq_printf(seq, "================================\n");
    seq_printf(seq, "Device Name: %s\n", dev->name);
    seq_printf(seq, "MAC Address: %pM\n", dev->dev_addr);
    seq_printf(seq, "MTU: %d\n", dev->mtu);
    seq_printf(seq, "IRQ: %d\n", dev->irq);
    seq_printf(seq, "Flags: 0x%08x\n", dev->flags);
    seq_printf(seq, "Features: 0x%08x\n", (u32)dev->features);

    seq_printf(seq, "\nStatistics:\n");
    seq_printf(seq, "  RX Packets: %llu\n", priv->stats.rx_packets);
    seq_printf(seq, "  RX Bytes: %llu\n", priv->stats.rx_bytes);
    seq_printf(seq, "  TX Packets: %llu\n", priv->stats.tx_packets);
    seq_printf(seq, "  TX Bytes: %llu\n", priv->stats.tx_bytes);
    seq_printf(seq, "  RX Errors: %llu\n", priv->stats.rx_errors);
    seq_printf(seq, "  TX Errors: %llu\n", priv->stats.tx_errors);

    return 0;
}

static const struct file_operations my_net_debug_fops = {
    .open = my_net_debug_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
```

## 7. 驱动示例和测试

### 7.1 完整驱动示例

```c
// 简单的网络驱动示例
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>

#define MY_NET_DRV_NAME "mynet"
#define MY_NET_TX_DESC_NUM 64
#define MY_NET_RX_DESC_NUM 128
#define MY_NET_RX_BUF_SIZE 2048

struct my_net_priv {
    struct net_device *dev;
    struct platform_device *pdev;
    struct napi_struct napi;

    // 描述符和缓冲区
    struct my_net_desc *tx_desc;
    struct my_net_desc *rx_desc;
    dma_addr_t tx_desc_dma;
    dma_addr_t rx_desc_dma;

    struct sk_buff **tx_skb;
    struct sk_buff **rx_skb;
    dma_addr_t *tx_dma;
    dma_addr_t *rx_dma;
    void **rx_buf;

    // 队列指针
    int tx_head, tx_tail;
    int rx_head;

    // 统计信息
    struct rtnl_link_stats64 stats;
    struct u64_stats_sync syncp;
};

// 驱动操作函数
static const struct net_device_ops my_netdev_ops = {
    .ndo_open = my_net_open,
    .ndo_stop = my_net_stop,
    .ndo_start_xmit = my_net_start_xmit,
    .ndo_get_stats64 = my_net_get_stats64,
    .ndo_set_mac_address = eth_mac_addr,
    .ndo_validate_addr = eth_validate_addr,
};

// ethtool操作函数
static const struct ethtool_ops my_ethtool_ops = {
    .get_drvinfo = my_net_get_drvinfo,
    .get_link = my_net_get_link,
    .get_strings = my_net_get_strings,
    .get_sset_count = my_net_get_sset_count,
    .get_ethtool_stats = my_net_get_ethtool_stats,
};

// 模块初始化
module_init(my_net_driver_init);
module_exit(my_net_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("My Network Driver");
MODULE_VERSION("1.0");
```

### 7.2 驱动测试

```c
// 测试脚本示例
#!/bin/bash

echo "Testing My Network Driver"

# 加载驱动
insmod my_net.ko

# 检查设备是否创建
ifconfig -a | grep mynet
if [ $? -eq 0 ]; then
    echo "Network device created successfully"
else
    echo "Failed to create network device"
    rmmod my_net
    exit 1
fi

# 启用设备
ifconfig mynet up

# 设置IP地址
ifconfig mynet 192.168.1.100 netmask 255.255.255.0

# 测试网络连接
ping -c 4 192.168.1.1

# 检查统计信息
ethtool -S mynet

# 性能测试
iperf -s &
sleep 1
iperf -c 192.168.1.100 -t 10

# 清理
killall iperf
ifconfig mynet down
rmmod my_net

echo "Test completed"
```

## 8. 总结

网络驱动开发需要掌握以下关键技术：

1. **设备管理**：正确处理设备的生命周期和状态管理
2. **中断处理**：实现高效的中断处理和NAPI轮询
3. **DMA操作**：正确使用DMA进行数据传输
4. **数据包处理**：实现高效的数据包收发
5. **错误处理**：完善的错误处理和恢复机制
6. **性能优化**：通过多种技术优化驱动性能
7. **调试功能**：提供丰富的调试信息和工具

通过深入理解网络驱动框架和实现机制，开发者可以编写出高性能、稳定的网络驱动程序。

---

*本指南基于Linux 6.17内核源代码，涵盖了网络驱动开发的完整流程和最佳实践。*