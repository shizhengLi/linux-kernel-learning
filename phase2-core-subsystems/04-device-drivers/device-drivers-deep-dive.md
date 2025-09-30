# Linux内核设备驱动子系统深度解析

## 1. 设备驱动概述

Linux设备驱动子系统是连接硬件设备和操作系统的桥梁，为上层应用提供统一的设备访问接口。该子系统采用分层架构设计，支持多种设备类型和复杂的硬件交互。

### 1.1 设备驱动架构

```c
/* 设备驱动分层架构 */
/*
 * 用户应用程序
 *     ↓ (系统调用)
 * 系统调用接口 (open, read, write, ioctl等)
 *     ↓
 * 虚拟文件系统(VFS)
 *     ↓
 * 设备文件系统 (devtmpfs)
 *     ↓
 * 字符设备/块设备/网络设备
 *     ↓
 * 设备驱动框架
 *     ↓
 * 硬件设备
 */

/* 设备驱动核心组件 */
struct device;              /* 设备结构 */
struct device_driver;       /* 驱动结构 */
struct class;              /* 设备类 */
struct bus_type;           /* 总线类型 */
struct kobject;            /* 内核对象 */
struct kset;              /* 内核对象集合 */
```

### 1.2 设备类型分类

```c
/* 设备类型枚举 */
enum device_type {
    DEVICE_TYPE_CHAR,      /* 字符设备 */
    DEVICE_TYPE_BLOCK,     /* 块设备 */
    DEVICE_TYPE_NET,       /* 网络设备 */
    DEVICE_TYPE_MISC,      /* 杂项设备 */
    DEVICE_TYPE_PLATFORM,  /* 平台设备 */
    DEVICE_TYPE_USB,       /* USB设备 */
    DEVICE_TYPE_PCI,       /* PCI设备 */
};

/* 设备驱动注册状态 */
enum driver_state {
    DRIVER_STATE_UNREGISTERED,  /* 未注册 */
    DRIVER_STATE_REGISTERING,   /* 注册中 */
    DRIVER_STATE_REGISTERED,    /* 已注册 */
    DRIVER_STATE_BINDING,      /* 绑定中 */
    DRIVER_STATE_BOUND,        /* 已绑定 */
    DRIVER_STATE_UNBINDING,    /* 解绑中 */
    DRIVER_STATE_REMOVED,      /* 已移除 */
};
```

## 2. 字符设备驱动

### 2.1 字符设备基础

```c
/* 字符设备结构 */
struct cdev {
    struct kobject kobj;          /* 内核对象 */
    struct module *owner;          /* 拥有者模块 */
    const struct file_operations *ops; /* 文件操作 */
    struct list_head list;        /* 设备链表 */
    dev_t dev;                    /* 设备号 */
    unsigned int count;           /* 次设备号数量 */
};

/* 字符设备注册 */
static int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
    int error;

    /* 设置设备号 */
    p->dev = dev;
    p->count = count;

    /* 添加到字符设备哈希表 */
    error = kobj_map(cdev_map, dev, count, NULL,
             exact_match, exact_lock, p);
    if (error)
        return error;

    kobject_get(&p->kobj);
    return 0;
}

/* 字符设备注销 */
static void cdev_del(struct cdev *p)
{
    cdev_unmap(p->dev, p->count);
    kobject_put(&p->kobj);
}

/* 字符设备文件操作 */
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iterate) (struct file *, struct dir_context *);
    unsigned int (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
    int (*aio_fsync) (struct kiocb *, int datasync);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
    unsigned (*mmap_capabilities)(struct file *);
};
```

### 2.2 字符设备驱动实现

```c
/* 简单字符设备驱动示例 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "simple_char"
#define CLASS_NAME  "simple_char_class"
#define BUFFER_SIZE 1024

/* 设备结构 */
struct simple_char_dev {
    struct cdev cdev;            /* 字符设备 */
    struct device *device;       /* 设备 */
    struct class *class;         /* 设备类 */
    dev_t dev_num;              /* 设备号 */
    char buffer[BUFFER_SIZE];    /* 数据缓冲区 */
    int buffer_size;            /* 缓冲区大小 */
    struct mutex mutex;         /* 互斥锁 */
};

/* 全局设备 */
static struct simple_char_dev simple_dev;

/* 文件操作 */
static ssize_t simple_char_read(struct file *file, char __user *buf,
                  size_t count, loff_t *ppos)
{
    struct simple_char_dev *dev = &simple_dev;
    int bytes_to_read;
    ssize_t ret = 0;

    /* 检查位置是否超出范围 */
    if (*ppos >= dev->buffer_size)
        return 0;

    /* 计算可读取字节数 */
    bytes_to_read = min(count, (size_t)(dev->buffer_size - *ppos));

    /* 复制数据到用户空间 */
    if (copy_to_user(buf, dev->buffer + *ppos, bytes_to_read)) {
        ret = -EFAULT;
        goto out;
    }

    /* 更新位置 */
    *ppos += bytes_to_read;
    ret = bytes_to_read;

out:
    return ret;
}

static ssize_t simple_char_write(struct file *file, const char __user *buf,
                   size_t count, loff_t *ppos)
{
    struct simple_char_dev *dev = &simple_dev;
    int bytes_to_write;
    ssize_t ret = 0;

    /* 检查缓冲区是否已满 */
    if (*ppos >= BUFFER_SIZE)
        return -ENOSPC;

    /* 计算可写入字节数 */
    bytes_to_write = min(count, (size_t)(BUFFER_SIZE - *ppos));

    /* 从用户空间复制数据 */
    if (copy_from_user(dev->buffer + *ppos, buf, bytes_to_write)) {
        ret = -EFAULT;
        goto out;
    }

    /* 更新位置和大小 */
    *ppos += bytes_to_write;
    if (*ppos > dev->buffer_size)
        dev->buffer_size = *ppos;
    ret = bytes_to_write;

out:
    return ret;
}

static int simple_char_open(struct inode *inode, struct file *file)
{
    struct simple_char_dev *dev = container_of(inode->i_cdev,
                        struct simple_char_dev, cdev);

    /* 设置文件私有数据 */
    file->private_data = dev;

    /* 增加设备引用计数 */
    try_module_get(THIS_MODULE);

    return 0;
}

static int simple_char_release(struct inode *inode, struct file *file)
{
    struct simple_char_dev *dev = file->private_data;

    /* 减少设备引用计数 */
    module_put(THIS_MODULE);

    return 0;
}

/* 文件操作结构 */
static const struct file_operations simple_char_fops = {
    .owner = THIS_MODULE,
    .read = simple_char_read,
    .write = simple_char_write,
    .open = simple_char_open,
    .release = simple_char_release,
};

/* 初始化字符设备 */
static int simple_char_setup_cdev(struct simple_char_dev *dev)
{
    int error;
    dev_t devno = MKDEV(MAJOR(dev->dev_num), 0);

    /* 初始化字符设备 */
    cdev_init(&dev->cdev, &simple_char_fops);
    dev->cdev.owner = THIS_MODULE;

    /* 添加字符设备 */
    error = cdev_add(&dev->cdev, devno, 1);
    if (error) {
        printk(KERN_ERR "simple_char: Failed to add cdev\n");
        return error;
    }

    return 0;
}

/* 模块初始化 */
static int __init simple_char_init(void)
{
    int error;

    /* 初始化互斥锁 */
    mutex_init(&simple_dev.mutex);

    /* 分配设备号 */
    error = alloc_chrdev_region(&simple_dev.dev_num, 0, 1, DEVICE_NAME);
    if (error) {
        printk(KERN_ERR "simple_char: Failed to allocate device number\n");
        return error;
    }

    /* 创建设备类 */
    simple_dev.class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(simple_dev.class)) {
        error = PTR_ERR(simple_dev.class);
        goto unregister_chrdev;
    }

    /* 创建字符设备 */
    error = simple_char_setup_cdev(&simple_dev);
    if (error)
        goto destroy_class;

    /* 创建设备文件 */
    simple_dev.device = device_create(simple_dev.class, NULL,
                      simple_dev.dev_num, NULL,
                      DEVICE_NAME);
    if (IS_ERR(simple_dev.device)) {
        error = PTR_ERR(simple_dev.device);
        goto del_cdev;
    }

    /* 初始化缓冲区 */
    simple_dev.buffer_size = 0;
    memset(simple_dev.buffer, 0, BUFFER_SIZE);

    printk(KERN_INFO "simple_char: Device initialized\n");
    printk(KERN_INFO "simple_char: Major number: %d\n",
           MAJOR(simple_dev.dev_num));

    return 0;

del_cdev:
    cdev_del(&simple_dev.cdev);
destroy_class:
    class_destroy(simple_dev.class);
unregister_chrdev:
    unregister_chrdev_region(simple_dev.dev_num, 1);
    return error;
}

/* 模块退出 */
static void __exit simple_char_exit(void)
{
    /* 销毁设备文件 */
    device_destroy(simple_dev.class, simple_dev.dev_num);

    /* 删除字符设备 */
    cdev_del(&simple_dev.cdev);

    /* 销毁设备类 */
    class_destroy(simple_dev.class);

    /* 注销设备号 */
    unregister_chrdev_region(simple_dev.dev_num, 1);

    printk(KERN_INFO "simple_char: Device removed\n");
}

module_init(simple_char_init);
module_exit(simple_char_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple character device driver");
```

## 3. 块设备驱动

### 3.1 块设备基础

```c
/* 块设备结构 */
struct block_device {
    dev_t bd_dev;                /* 设备号 */
    int bd_openers;             /* 打开者计数 */
    struct inode *bd_inode;     /* 索引节点 */
    struct super_block *bd_super; /* 超级块 */
    struct mutex bd_mutex;      /* 互斥锁 */
    struct list_head bd_inodes;  /* 索引节点链表 */
    void *bd_holder;            /* 持有者 */
    int bd_holders;             /* 持有者计数 */
    struct block_device *bd_contains; /* 包含的块设备 */
    unsigned bd_block_size;     /* 块大小 */
    struct hd_struct *bd_part;  /* 分区信息 */
    unsigned bd_part_count;     /* 分区计数 */
    int bd_invalidated;         /* 是否无效 */
    struct gendisk *bd_disk;    /* 磁盘 */
    struct list_head bd_list;   /* 块设备链表 */
    struct backing_dev_info *bd_bdi; /* 回设备信息 */
    unsigned long bd_private;   /* 私有数据 */

    /* 等待队列 */
    spinlock_t bd_lock;         /* 自旋锁 */
    struct list_head bd_lru;    /* LRU链表 */
    struct atomic_t bd_count;   /* 引用计数 */
};

/* 请求队列结构 */
struct request_queue {
    struct list_head queue_head; /* 请求队列头部 */
    struct request *last_merge;  /* 最后合并的请求 */
    elevator_t elevator;         /* I/O调度器 */
    struct request_list rl;      /* 请求列表 */
    struct list_head drain_list; /* 排空列表 */
    struct list_head flush_queue; /* 刷新队列 */
    struct list_head flush_data_in_flight; /* 刷新数据传输中 */
    struct blk_flush_queue *fq; /* 刷新队列 */
    struct queue_limits limits;  /* 队列限制 */
    struct blk_mq_ops *mq_ops;   /* 多队列操作 */
    struct blk_mq_tag_set *tag_set; /* 标签集合 */
    struct list_head tag_set_list; /* 标签集合链表 */

    /* 锁机制 */
    spinlock_t queue_lock;      /* 队列锁 */
    struct kobject kobj;        /* 内核对象 */

    /* 状态标志 */
    unsigned long queue_flags;   /* 队列标志 */
    gfp_t bounce_gfp;           /* 弹跳GFP标志 */

    /* 统计信息 */
    struct blk_rq_stat stat[2]; /* 请求统计 */
    struct timer_list timeout;  /* 超时定时器 */
    struct work_struct timeout_work; /* 超时工作 */

    /* 调度器相关 */
    struct lock_class_key key;  /* 锁类键 */
    struct lockdep_map lockdep_map; /* 锁依赖映射 */
};

/* 块设备操作 */
struct block_device_operations {
    int (*open) (struct block_device *, fmode_t);
    int (*release) (struct gendisk *, fmode_t);
    int (*ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    int (*compat_ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    int (*direct_access) (struct block_device *, sector_t,
                    void **, unsigned long *);
    unsigned int (*check_events) (struct gendisk *disk,
                      unsigned int clearing);
    void (*unlock_native_capacity) (struct gendisk *);
    int (*revalidate_disk) (struct gendisk *);
    int (*getgeo)(struct block_device *, struct hd_geometry *);
    void (*swap_slot_free_notify) (struct block_device *, unsigned long);
    struct module *owner;
    const struct pr_ops *pr_ops;
};
```

### 3.2 块设备驱动实现

```c
/* 简单块设备驱动示例 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "simple_blk"
#define SECTOR_SIZE 512
#define DEVICE_SIZE (1 * 1024 * 1024) /* 1MB */
#define NR_SECTORS (DEVICE_SIZE / SECTOR_SIZE)

/* 设备结构 */
struct simple_blk_dev {
    struct gendisk *gd;         /* 磁盘 */
    struct request_queue *queue; /* 请求队列 */
    spinlock_t lock;            /* 自旋锁 */
    unsigned char *data;         /* 设备数据 */
    int device_size;            /* 设备大小 */
};

/* 全局设备 */
static struct simple_blk_dev simple_blk_dev;

/* 处理块设备请求 */
static void simple_blk_request(struct request_queue *q)
{
    struct request *req;
    struct bio_vec bvec;
    struct bvec_iter iter;
    sector_t sector;
    unsigned long offset;
    int bytes_to_transfer;
    int direction;
    int error = 0;

    /* 获取下一个请求 */
    req = blk_fetch_request(q);
    if (!req)
        return;

    /* 检查请求是否有效 */
    if (blk_rq_pos(req) + blk_rq_sectors(req) > get_capacity(req->rq_disk)) {
        printk(KERN_ERR "simple_blk: Invalid request\n");
        __blk_end_request_all(req, -EIO);
        return;
    }

    /* 处理请求 */
    direction = rq_data_dir(req);
    sector = blk_rq_pos(req);

    /* 遍历所有段 */
    rq_for_each_segment(bvec, req, iter) {
        /* 计算偏移量 */
        offset = sector * SECTOR_SIZE;

        /* 检查偏移量是否有效 */
        if (offset + bvec.bv_len > simple_blk_dev.device_size) {
            printk(KERN_ERR "simple_blk: Offset out of range\n");
            error = -EIO;
            break;
        }

        /* 处理读写 */
        if (direction == READ) {
            /* 从设备读取到内存 */
            memcpy(page_address(bvec.bv_page) + bvec.bv_offset,
                   simple_blk_dev.data + offset,
                   bvec.bv_len);
        } else {
            /* 从内存写入到设备 */
            memcpy(simple_blk_dev.data + offset,
                   page_address(bvec.bv_page) + bvec.bv_offset,
                   bvec.bv_len);
        }

        /* 更新扇区数 */
        sector += bvec.bv_len / SECTOR_SIZE;
    }

    /* 结束请求 */
    if (!__blk_end_request_cur(req, error)) {
        /* 还有更多请求需要处理 */
        simple_blk_request(q);
    }
}

/* 获取设备信息 */
static int simple_blk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
    /* 设置磁盘几何信息 */
    geo->heads = 2;
    geo->sectors = 4;
    geo->cylinders = get_capacity(bdev->bd_disk) / (geo->heads * geo->sectors);
    geo->start = 0;

    return 0;
}

/* 块设备操作 */
static const struct block_device_operations simple_blk_ops = {
    .owner = THIS_MODULE,
    .getgeo = simple_blk_getgeo,
};

/* 创建块设备 */
static int simple_blk_setup_device(struct simple_blk_dev *dev)
{
    int error;

    /* 分配数据内存 */
    dev->data = vmalloc(dev->device_size);
    if (!dev->data) {
        printk(KERN_ERR "simple_blk: Failed to allocate device memory\n");
        return -ENOMEM;
    }

    /* 清空数据 */
    memset(dev->data, 0, dev->device_size);

    /* 初始化自旋锁 */
    spin_lock_init(&dev->lock);

    /* 创建请求队列 */
    dev->queue = blk_init_queue(simple_blk_request, &dev->lock);
    if (!dev->queue) {
        printk(KERN_ERR "simple_blk: Failed to create request queue\n");
        error = -ENOMEM;
        goto free_data;
    }

    /* 设置队列参数 */
    blk_queue_logical_block_size(dev->queue, SECTOR_SIZE);
    dev->queue->queuedata = dev;

    /* 分配磁盘 */
    dev->gd = alloc_disk(1);
    if (!dev->gd) {
        printk(KERN_ERR "simple_blk: Failed to allocate disk\n");
        error = -ENOMEM;
        goto cleanup_queue;
    }

    /* 设置磁盘参数 */
    dev->gd->major = MAJOR(dev->dev->dev);
    dev->gd->first_minor = 0;
    dev->gd->fops = &simple_blk_ops;
    dev->gd->queue = dev->queue;
    dev->gd->private_data = dev;
    snprintf(dev->gd->disk_name, 32, DEVICE_NAME);

    /* 设置磁盘容量 */
    set_capacity(dev->gd, NR_SECTORS);

    /* 添加磁盘 */
    add_disk(dev->gd);

    return 0;

cleanup_queue:
    blk_cleanup_queue(dev->queue);
free_data:
    vfree(dev->data);
    return error;
}

/* 模块初始化 */
static int __init simple_blk_init(void)
{
    int error;

    /* 设置设备大小 */
    simple_blk_dev.device_size = DEVICE_SIZE;

    /* 分配设备号 */
    error = alloc_chrdev_region(&simple_blk_dev.dev, 0, 1, DEVICE_NAME);
    if (error) {
        printk(KERN_ERR "simple_blk: Failed to allocate device number\n");
        return error;
    }

    /* 创建块设备 */
    error = simple_blk_setup_device(&simple_blk_dev);
    if (error) {
        unregister_chrdev_region(simple_blk_dev.dev, 1);
        return error;
    }

    printk(KERN_INFO "simple_blk: Device initialized\n");
    printk(KERN_INFO "simple_blk: Major number: %d\n",
           MAJOR(simple_blk_dev.dev));
    printk(KERN_INFO "simple_blk: Device size: %d bytes\n",
           simple_blk_dev.device_size);

    return 0;
}

/* 模块退出 */
static void __exit simple_blk_exit(void)
{
    /* 删除磁盘 */
    if (simple_blk_dev.gd) {
        del_gendisk(simple_blk_dev.gd);
        put_disk(simple_blk_dev.gd);
    }

    /* 清理请求队列 */
    if (simple_blk_dev.queue)
        blk_cleanup_queue(simple_blk_dev.queue);

    /* 释放数据内存 */
    if (simple_blk_dev.data)
        vfree(simple_blk_dev.data);

    /* 注销设备号 */
    unregister_chrdev_region(simple_blk_dev.dev, 1);

    printk(KERN_INFO "simple_blk: Device removed\n");
}

module_init(simple_blk_init);
module_exit(simple_blk_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple block device driver");
```

## 4. 网络设备驱动

### 4.1 网络设备基础

```c
/* 网络设备结构 */
struct net_device {
    char name[IFNAMSIZ];        /* 设备名称 */
    struct hlist_node name_hlist; /* 名称哈希表 */
    struct dev_ifalias __rcu *ifalias; /* 接口别名 */

    /* 设备状态 */
    unsigned long state;         /* 设备状态 */
    struct list_head dev_list;   /* 设备链表 */
    struct list_head napi_list;  /* NAPI链表 */

    /* 网络参数 */
    unsigned int mtu;           /* 最大传输单元 */
    unsigned short type;        /* 硬件类型 */
    unsigned short hard_header_len; /* 硬件头部长度 */
    unsigned char perm_addr[MAX_ADDR_LEN]; /* 永久地址 */
    unsigned char addr_len;      /* 地址长度 */
    unsigned short neigh_priv_len; /* 邻居私有长度 */
    unsigned short dev_id;      /* 设备ID */

    /* 操作函数 */
    const struct net_device_ops *netdev_ops; /* 网络设备操作 */
    const struct ethtool_ops *ethtool_ops; /* ethtool操作 */
    const struct header_ops *header_ops; /* 头部操作 */

    /* 统计信息 */
    struct rtnl_link_stats64 stats; /* 路由链路统计 */
    atomic_long_t rx_dropped;  /* 丢弃的接收包 */
    atomic_long_t tx_dropped;  /* 丢弃的发送包 */

    /* 队列管理 */
    struct netdev_queue *_tx;   /* 发送队列 */
    unsigned int num_tx_queues; /* 发送队列数 */
    struct netdev_queue rx_queue; /* 接收队列 */
    unsigned int real_num_tx_queues; /* 实际发送队列数 */

    /* NAPI相关 */
    struct napi_struct napi;   /* NAPI结构 */
    gro_result_t (*gro_receive)(struct napi_struct *napi,
                    struct sk_buff *skb);
    int (*gro_complete)(struct sk_buff *skb,
                int nhoff);

    /* 中断处理 */
    int irq;                    /* 中断号 */
    void *dev_id;              /* 设备ID */
    unsigned char dma;          /* DMA标志 */
    unsigned char perm_addr[MAX_ADDR_LEN]; /* 永久地址 */

    /* 硬件相关 */
    unsigned long features;      /* 硬件特性 */
    unsigned long hw_features;   /* 硬件特性 */
    unsigned long wanted_features; /* 期望特性 */
    unsigned long vlan_features; /* VLAN特性 */
    unsigned long hw_enc_features; /* 硬件封装特性 */

    /* 私有数据 */
    void *priv;                 /* 驱动私有数据 */
    const struct net_device_ops *netdev_ops; /* 网络设备操作 */
    const struct ethtool_ops *ethtool_ops; /* ethtool操作 */
};

/* 网络设备操作 */
struct net_device_ops {
    int (*ndo_init)(struct net_device *dev);
    void (*ndo_uninit)(struct net_device *dev);
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
                   struct net_device *dev);
    u16 (*ndo_select_queue)(struct net_device *dev,
                   struct sk_buff *skb,
                   struct net_device *sb_dev);
    void (*ndo_change_rx_flags)(struct net_device *dev,
                   int flags);
    void (*ndo_set_rx_mode)(struct net_device *dev);
    int (*ndo_set_mac_address)(struct net_device *dev,
                   void *addr);
    int (*ndo_validate_addr)(struct net_device *dev);
    int (*ndo_do_ioctl)(struct net_device *dev,
                   struct ifreq *ifr, int cmd);
    int (*ndo_set_config)(struct net_device *dev,
                   struct ifmap *map);
    int (*ndo_change_mtu)(struct net_device *dev,
                   int new_mtu);
    int (*ndo_neigh_setup)(struct net_device *dev,
                   struct neigh_parms *);
    void (*ndo_tx_timeout)(struct net_device *dev);

    /* ... 更多操作 */
};

/* 数据包结构 */
struct sk_buff {
    /* 链表管理 */
    struct sk_buff *next;       /* 下一个skb */
    struct sk_buff *prev;       /* 上一个skb */
    struct sock *sk;            /* 套接字 */
    ktime_t tstamp;             /* 时间戳 */
    struct rb_node rbnode;      /* 红黑树节点 */
    unsigned long _skb_refdst;  /* 引用目标 */
    struct sec_path *sp;        /* 安全路径 */

    /* 数据区域 */
    char cb[48] __aligned(8);    /* 控制缓冲区 */
    unsigned int len,           /* 数据长度 */
             data_len;         /* 非线性数据长度 */
    __u16 mac_len,              /* MAC头部长度 */
        hdr_len;                /* 网络头部长度 */
    void *data;                 /* 数据指针 */
    struct sk_buff *frag_next;  /* 下一个分片 */

    /* 协议相关 */
    __u16 protocol;             /* 协议类型 */
    __u16 transport_header;     /* 传输层头部偏移 */
    __u16 network_header;       /* 网络层头部偏移 */
    __u16 mac_header;           /* MAC层头部偏移 */

    /* 设备相关 */
    netdev_features_t features; /* 设备特性 */
    __u32 priority;             /* 优先级 */
    __u16 vlan_tci;             /* VLAN TCI */
    __u16 queue_mapping;        /* 队列映射 */
    __u8 tc_index;              /* 流量控制索引 */
    __u8 tc_verd;               /* 流量控制版本 */

    /* 路由相关 */
    struct dst_entry *dst;      /* 路由表项 */
    struct sec_path *sp;         /* 安全路径 */

    /* ... 更多字段 */
};
```

### 4.2 网络设备驱动实现

```c
/* 简单网络设备驱动示例 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#define DEVICE_NAME "simple_net"
#define DEVICE_MTU 1500
#define RX_RING_SIZE 256
#define TX_RING_SIZE 256

/* 描述符结构 */
struct simple_net_desc {
    dma_addr_t dma;             /* DMA地址 */
    struct sk_buff *skb;        /* 套接字缓冲区 */
    u32 flags;                  /* 标志 */
    u32 len;                    /* 长度 */
};

/* 环形缓冲区 */
struct simple_net_ring {
    struct simple_net_desc *desc; /* 描述符数组 */
    dma_addr_t dma;             /* DMA地址 */
    u32 size;                   /* 环形缓冲区大小 */
    u32 head;                   /* 头部索引 */
    u32 tail;                   /* 尾部索引 */
};

/* 设备结构 */
struct simple_net_dev {
    struct net_device *ndev;     /* 网络设备 */
    struct net_device_stats stats; /* 网络统计 */
    struct simple_net_ring rx_ring; /* 接收环形缓冲区 */
    struct simple_net_ring tx_ring; /* 发送环形缓冲区 */
    struct napi_struct napi;    /* NAPI结构 */
    struct device *device;       /* 设备 */
    void __iomem *base_addr;     /* 基地址 */
    int irq;                     /* 中断号 */
    spinlock_t lock;            /* 自旋锁 */
};

/* 网络设备操作 */
static const struct net_device_ops simple_net_ops = {
    .ndo_open = simple_net_open,
    .ndo_stop = simple_net_stop,
    .ndo_start_xmit = simple_net_start_xmit,
    .ndo_get_stats64 = simple_net_get_stats64,
    .ndo_set_mac_address = eth_mac_addr,
    .ndo_validate_addr = eth_validate_addr,
};

/* 初始化环形缓冲区 */
static int simple_net_init_ring(struct simple_net_ring *ring, int size)
{
    /* 分配描述符数组 */
    ring->desc = dma_alloc_coherent(NULL,
                     size * sizeof(struct simple_net_desc),
                     &ring->dma, GFP_KERNEL);
    if (!ring->desc)
        return -ENOMEM;

    ring->size = size;
    ring->head = 0;
    ring->tail = 0;

    return 0;
}

/* 释放环形缓冲区 */
static void simple_net_free_ring(struct simple_net_ring *ring)
{
    if (ring->desc) {
        dma_free_coherent(NULL,
                 ring->size * sizeof(struct simple_net_desc),
                 ring->desc, ring->dma);
        ring->desc = NULL;
    }
}

/* 分配接收缓冲区 */
static int simple_net_alloc_rx_buffers(struct simple_net_dev *dev)
{
    struct simple_net_ring *ring = &dev->rx_ring;
    struct simple_net_desc *desc;
    struct sk_buff *skb;
    int i;

    for (i = 0; i < ring->size; i++) {
        skb = netdev_alloc_skb_ip_align(dev->ndev, dev->ndev->mtu);
        if (!skb)
            return -ENOMEM;

        desc = &ring->desc[i];
        desc->skb = skb;
        desc->dma = dma_map_single(dev->device, skb->data,
                      skb->len, DMA_FROM_DEVICE);
        desc->flags = 0;
        desc->len = skb->len;
    }

    return 0;
}

/* 发送数据包 */
static netdev_tx_t simple_net_start_xmit(struct sk_buff *skb,
                     struct net_device *ndev)
{
    struct simple_net_dev *dev = netdev_priv(ndev);
    struct simple_net_ring *ring = &dev->tx_ring;
    struct simple_net_desc *desc;
    unsigned long flags;
    int entry;

    /* 检查发送队列是否已满 */
    spin_lock_irqsave(&dev->lock, flags);
    entry = ring->head;
    if (ring->desc[entry].skb) {
        spin_unlock_irqrestore(&dev->lock, flags);
        return NETDEV_TX_BUSY;
    }

    /* 设置发送描述符 */
    desc = &ring->desc[entry];
    desc->skb = skb;
    desc->dma = dma_map_single(dev->device, skb->data,
                  skb->len, DMA_TO_DEVICE);
    desc->len = skb->len;
    desc->flags = DESC_FLAG_OWN;

    /* 更新头部指针 */
    ring->head = (ring->head + 1) % ring->size;

    /* 更新统计信息 */
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    /* 启动发送 */
    writel(1, dev->base_addr + TX_START_REG);

    spin_unlock_irqrestore(&dev->lock, flags);

    return NETDEV_TX_OK;
}

/* 接收数据包 */
static int simple_net_poll(struct napi_struct *napi, int budget)
{
    struct simple_net_dev *dev = container_of(napi, struct simple_net_dev, napi);
    struct simple_net_ring *ring = &dev->rx_ring;
    struct simple_net_desc *desc;
    struct sk_buff *skb;
    int work_done = 0;

    while (work_done < budget) {
        /* 检查是否有数据包 */
        desc = &ring->desc[ring->tail];
        if (desc->flags & DESC_FLAG_OWN)
            break;

        /* 处理数据包 */
        skb = desc->skb;
        if (skb) {
            /* 解除DMA映射 */
            dma_unmap_single(dev->device, desc->dma,
                     desc->len, DMA_FROM_DEVICE);

            /* 设置数据包信息 */
            skb_put(skb, desc->len);
            skb->protocol = eth_type_trans(skb, dev->ndev);

            /* 传递给网络栈 */
            netif_receive_skb(skb);

            /* 更新统计信息 */
            dev->stats.rx_packets++;
            dev->stats.rx_bytes += desc->len;
        }

        /* 分配新的缓冲区 */
        skb = netdev_alloc_skb_ip_align(dev->ndev, dev->ndev->mtu);
        if (!skb) {
            printk(KERN_ERR "simple_net: Failed to allocate RX buffer\n");
            break;
        }

        /* 设置新的描述符 */
        desc->skb = skb;
        desc->dma = dma_map_single(dev->device, skb->data,
                      skb->len, DMA_FROM_DEVICE);
        desc->flags = 0;
        desc->len = skb->len;

        /* 更新尾部指针 */
        ring->tail = (ring->tail + 1) % ring->size;
        work_done++;
    }

    /* 如果还有工作要做，返回work_done */
    if (work_done < budget) {
        napi_complete(napi);
        writel(1, dev->base_addr + RX_ENABLE_REG);
    }

    return work_done;
}

/* 中断处理函数 */
static irqreturn_t simple_net_interrupt(int irq, void *dev_id)
{
    struct simple_net_dev *dev = dev_id;
    u32 status;

    /* 读取中断状态 */
    status = readl(dev->base_addr + INT_STATUS_REG);
    if (!status)
        return IRQ_NONE;

    /* 清除中断 */
    writel(status, dev->base_addr + INT_CLEAR_REG);

    /* 处理接收中断 */
    if (status & INT_RX_COMPLETE) {
        /* 禁用接收中断 */
        writel(0, dev->base_addr + RX_INT_ENABLE_REG);
        /* 调度NAPI */
        napi_schedule(&dev->napi);
    }

    /* 处理发送完成中断 */
    if (status & INT_TX_COMPLETE) {
        struct simple_net_ring *ring = &dev->tx_ring;
        struct simple_net_desc *desc;

        /* 清理已发送的描述符 */
        while (ring->tail != ring->head) {
            desc = &ring->desc[ring->tail];
            if (desc->flags & DESC_FLAG_OWN)
                break;

            if (desc->skb) {
                dev_kfree_skb_irq(desc->skb);
                desc->skb = NULL;
            }

            ring->tail = (ring->tail + 1) % ring->size;
        }

        /* 唤醒发送队列 */
        netif_wake_queue(dev->ndev);
    }

    return IRQ_HANDLED;
}

/* 打开设备 */
static int simple_net_open(struct net_device *ndev)
{
    struct simple_net_dev *dev = netdev_priv(ndev);
    int error;

    /* 分配接收缓冲区 */
    error = simple_net_alloc_rx_buffers(dev);
    if (error)
        return error;

    /* 启用NAPI */
    napi_enable(&dev->napi);

    /* 启用接收 */
    writel(1, dev->base_addr + RX_ENABLE_REG);
    writel(1, dev->base_addr + RX_INT_ENABLE_REG);

    /* 启用发送 */
    writel(1, dev->base_addr + TX_ENABLE_REG);
    writel(1, dev->base_addr + TX_INT_ENABLE_REG);

    /* 启用中断 */
    error = request_irq(dev->irq, simple_net_interrupt, IRQF_SHARED,
               DEVICE_NAME, dev);
    if (error) {
        napi_disable(&dev->napi);
        return error;
    }

    /* 启用网络接口 */
    netif_start_queue(ndev);

    return 0;
}

/* 停止设备 */
static int simple_net_stop(struct net_device *ndev)
{
    struct simple_net_dev *dev = netdev_priv(ndev);

    /* 禁用网络接口 */
    netif_stop_queue(ndev);

    /* 禁用中断 */
    free_irq(dev->irq, dev);

    /* 禁用接收 */
    writel(0, dev->base_addr + RX_ENABLE_REG);
    writel(0, dev->base_addr + RX_INT_ENABLE_REG);

    /* 禁用发送 */
    writel(0, dev->base_addr + TX_ENABLE_REG);
    writel(0, dev->base_addr + TX_INT_ENABLE_REG);

    /* 禁用NAPI */
    napi_disable(&dev->napi);

    return 0;
}

/* 获取统计信息 */
static struct net_device_stats *simple_net_get_stats64(struct net_device *ndev,
                               struct rtnl_link_stats64 *stats)
{
    struct simple_net_dev *dev = netdev_priv(ndev);

    /* 复制统计信息 */
    memcpy(stats, &dev->stats, sizeof(*stats));

    return stats;
}

/* 模块初始化 */
static int __init simple_net_init(void)
{
    struct simple_net_dev *dev;
    struct net_device *ndev;
    int error;

    /* 分配网络设备 */
    ndev = alloc_etherdev(sizeof(struct simple_net_dev));
    if (!ndev) {
        printk(KERN_ERR "simple_net: Failed to allocate net device\n");
        return -ENOMEM;
    }

    /* 设置设备信息 */
    SET_NETDEV_DEV(ndev, &platform_device->dev);
    dev = netdev_priv(ndev);
    dev->ndev = ndev;
    dev->device = &platform_device->dev;
    dev->base_addr = (void __iomem *)0x10000000; /* 示例地址 */
    dev->irq = 16; /* 示例中断号 */

    /* 初始化自旋锁 */
    spin_lock_init(&dev->lock);

    /* 初始化NAPI */
    netif_napi_add(ndev, &dev->napi, simple_net_poll, 64);

    /* 设置网络设备操作 */
    ndev->netdev_ops = &simple_net_ops;
    ndev->ethtool_ops = &simple_net_ethtool_ops;

    /* 设置MAC地址 */
    eth_hw_addr_random(ndev);

    /* 设置MTU */
    ndev->mtu = DEVICE_MTU;

    /* 初始化环形缓冲区 */
    error = simple_net_init_ring(&dev->rx_ring, RX_RING_SIZE);
    if (error)
        goto free_device;

    error = simple_net_init_ring(&dev->tx_ring, TX_RING_SIZE);
    if (error)
        goto free_rx_ring;

    /* 注册网络设备 */
    error = register_netdev(ndev);
    if (error)
        goto free_tx_ring;

    printk(KERN_INFO "simple_net: Device initialized\n");
    printk(KERN_INFO "simple_net: MAC address: %pM\n", ndev->dev_addr);

    return 0;

free_tx_ring:
    simple_net_free_ring(&dev->tx_ring);
free_rx_ring:
    simple_net_free_ring(&dev->rx_ring);
free_device:
    free_netdev(ndev);
    return error;
}

/* 模块退出 */
static void __exit simple_net_exit(void)
{
    struct simple_net_dev *dev = netdev_priv(ndev);

    /* 注销网络设备 */
    unregister_netdev(dev->ndev);

    /* 释放环形缓冲区 */
    simple_net_free_ring(&dev->rx_ring);
    simple_net_free_ring(&dev->tx_ring);

    /* 释放网络设备 */
    free_netdev(dev->ndev);

    printk(KERN_INFO "simple_net: Device removed\n");
}

module_init(simple_net_init);
module_exit(simple_net_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple network device driver");
```

## 5. 设备模型

### 5.1 sysfs和设备模型

```c
/* 内核对象结构 */
struct kobject {
    const char *name;            /* 对象名称 */
    struct list_head entry;      /* 链表项 */
    struct kobject *parent;      /* 父对象 */
    struct kset *kset;           /* 对象集合 */
    struct kobj_type *ktype;     /* 对象类型 */
    struct sysfs_dirent *sd;     /* sysfs目录项 */
    struct kref kref;            /* 引用计数 */
    unsigned int state_initialized:1; /* 已初始化 */
    unsigned int state_in_sysfs:1;    /* 在sysfs中 */
    unsigned int state_add_uevent_sent:1; /* 添加事件已发送 */
    unsigned int state_remove_uevent_sent:1; /* 移除事件已发送 */
    unsigned int uevent_suppress:1;      /* 禁用事件 */
};

/* 对象类型 */
struct kobj_type {
    void (*release)(struct kobject *kobj); /* 释放函数 */
    const struct sysfs_ops *sysfs_ops;   /* sysfs操作 */
    const struct attribute **default_attrs; /* 默认属性 */
};

/* sysfs操作 */
struct sysfs_ops {
    ssize_t (*show)(struct kobject *, struct attribute *, char *);
    ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

/* 属性结构 */
struct attribute {
    const char *name;            /* 属性名称 */
    umode_t mode;               /* 权限模式 */
};

/* 设备结构 */
struct device {
    struct device *parent;       /* 父设备 */
    struct device_private *p;    /* 私有数据 */
    const char *init_name;      /* 初始名称 */
    const struct device_type *type; /* 设备类型 */
    struct bus_type *bus;        /* 总线类型 */
    struct driver_state driver; /* 驱动状态 */
    void *platform_data;        /* 平台数据 */
    void *driver_data;          /* 驱动数据 */
    struct dev_links_info links; /* 设备链接信息 */
    struct dev_pm_info power;   /* 电源管理信息 */
    struct dev_pm_domain *pm_domain; /* 电源管理域 */

    /* sysfs相关 */
    struct kobject kobj;        /* 内核对象 */
    const char *bus_id;         /* 总线ID */
    struct device_node *of_node; /* 设备树节点 */

    /* DMA相关 */
    struct dma_coherent_mem *dma_mem; /* DMA一致性内存 */
    u64 *dma_mask;              /* DMA掩码 */
    u64 coherent_dma_mask;     /* 一致性DMA掩码 */
    unsigned long dma_pfn_offset; /* DMA页帧偏移 */

    /* 驱动相关 */
    struct device_driver *driver; /* 设备驱动 */
    u32 id;                     /* 设备ID */
    spinlock_t devres_lock;     /* 设备资源锁 */
    struct list_head devres_head; /* 设备资源链表 */

    /* 状态信息 */
    bool offline_disabled:1;    /* 离线禁用 */
    bool offline:1;             /* 离线 */
    bool of_node_reused:1;      /* 设备树节点重用 */
    bool state_synced:1;        /* 状态同步 */
    bool can_match:1;           /* 可以匹配 */

    /* ... 更多字段 */
};

/* 驱动结构 */
struct device_driver {
    const char *name;           /* 驱动名称 */
    struct bus_type *bus;       /* 总线类型 */
    struct module *owner;       /* 拥有者模块 */
    const char *mod_name;       /* 模块名称 */
    bool suppress_bind_attrs;   /* 禁止绑定属性 */
    const struct of_device_id *of_match_table; /* 设备树匹配表 */
    const struct acpi_device_id *acpi_match_table; /* ACPI匹配表 */

    /* 驱动操作 */
    int (*probe)(struct device *dev); /* 探测函数 */
    int (*remove)(struct device *dev); /* 移除函数 */
    void (*shutdown)(struct device *dev); /* 关闭函数 */
    int (*suspend)(struct device *dev, pm_message_t state); /* 挂起函数 */
    int (*resume)(struct device *dev); /* 恢复函数 */
    const struct attribute_group **groups; /* 属性组 */
    const struct dev_pm_ops *pm; /* 电源管理操作 */

    /* 驱动核心相关 */
    struct driver_private *p;   /* 私有数据 */
};
```

### 5.2 平台设备和驱动

```c
/* 平台设备结构 */
struct platform_device {
    const char *name;           /* 设备名称 */
    int id;                     /* 设备ID */
    struct device dev;          /* 设备结构 */
    u32 num_resources;          /* 资源数量 */
    struct resource *resource;  /* 资源数组 */
    const struct platform_device_id *id_entry; /* ID条目 */
    char *driver_override;      /* 驱动覆盖 */
    struct mfd_cell *mfd_cell;  /* MFD单元 */
    struct pdev_archdata archdata; /* 架构相关数据 */
};

/* 平台驱动结构 */
struct platform_driver {
    int (*probe)(struct platform_device *); /* 探测函数 */
    int (*remove)(struct platform_device *); /* 移除函数 */
    void (*shutdown)(struct platform_device *); /* 关闭函数 */
    int (*suspend)(struct platform_device *, pm_message_t state); /* 挂起函数 */
    int (*resume)(struct platform_device *); /* 恢复函数 */
    struct device_driver driver; /* 设备驱动 */
    const struct platform_device_id *id_table; /* ID表 */
    bool prevent_deferred_probe; /* 防止延迟探测 */
};

/* 平台设备示例 */
static struct resource simple_platform_resources[] = {
    [0] = {
        .start = 0x10000000,    /* 起始地址 */
        .end   = 0x1000FFFF,    /* 结束地址 */
        .flags = IORESOURCE_MEM, /* 内存资源 */
    },
    [1] = {
        .start = 16,            /* 中断号 */
        .end   = 16,            /* 中断号 */
        .flags = IORESOURCE_IRQ, /* 中断资源 */
    },
};

/* 平台设备定义 */
static struct platform_device simple_platform_device = {
    .name = "simple_platform",
    .id = -1,
    .num_resources = ARRAY_SIZE(simple_platform_resources),
    .resource = simple_platform_resources,
};

/* 平台驱动探测函数 */
static int simple_platform_probe(struct platform_device *pdev)
{
    struct resource *mem_res;
    struct resource *irq_res;
    void __iomem *base_addr;
    int irq;
    int error;

    /* 获取内存资源 */
    mem_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (!mem_res) {
        printk(KERN_ERR "simple_platform: Failed to get memory resource\n");
        return -ENODEV;
    }

    /* 获取中断资源 */
    irq_res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
    if (!irq_res) {
        printk(KERN_ERR "simple_platform: Failed to get IRQ resource\n");
        return -ENODEV;
    }

    /* 请求内存区域 */
    error = request_mem_region(mem_res->start, resource_size(mem_res),
                 pdev->name);
    if (!error) {
        printk(KERN_ERR "simple_platform: Failed to request memory region\n");
        return -EBUSY;
    }

    /* 映射内存 */
    base_addr = ioremap(mem_res->start, resource_size(mem_res));
    if (!base_addr) {
        printk(KERN_ERR "simple_platform: Failed to map memory\n");
        error = -ENOMEM;
        goto release_mem;
    }

    /* 获取中断号 */
    irq = irq_res->start;

    /* 初始化设备 */
    error = simple_platform_init(base_addr, irq);
    if (error) {
        printk(KERN_ERR "simple_platform: Failed to initialize device\n");
        goto unmap_mem;
    }

    /* 保存私有数据 */
    platform_set_drvdata(pdev, base_addr);

    printk(KERN_INFO "simple_platform: Device probed\n");
    printk(KERN_INFO "simple_platform: Base address: 0x%p\n", base_addr);
    printk(KERN_INFO "simple_platform: IRQ: %d\n", irq);

    return 0;

unmap_mem:
    iounmap(base_addr);
release_mem:
    release_mem_region(mem_res->start, resource_size(mem_res));
    return error;
}

/* 平台驱动移除函数 */
static int simple_platform_remove(struct platform_device *pdev)
{
    void __iomem *base_addr = platform_get_drvdata(pdev);
    struct resource *mem_res;

    /* 清理设备 */
    simple_platform_cleanup();

    /* 取消映射 */
    iounmap(base_addr);

    /* 释放内存区域 */
    mem_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (mem_res) {
        release_mem_region(mem_res->start, resource_size(mem_res));
    }

    printk(KERN_INFO "simple_platform: Device removed\n");
    return 0;
}

/* 平台驱动定义 */
static struct platform_driver simple_platform_driver = {
    .probe = simple_platform_probe,
    .remove = simple_platform_remove,
    .driver = {
        .name = "simple_platform",
        .owner = THIS_MODULE,
    },
};

/* 模块初始化 */
static int __init simple_platform_init_module(void)
{
    int error;

    /* 注册平台设备 */
    error = platform_device_register(&simple_platform_device);
    if (error) {
        printk(KERN_ERR "simple_platform: Failed to register device\n");
        return error;
    }

    /* 注册平台驱动 */
    error = platform_driver_register(&simple_platform_driver);
    if (error) {
        printk(KERN_ERR "simple_platform: Failed to register driver\n");
        platform_device_unregister(&simple_platform_device);
        return error;
    }

    printk(KERN_INFO "simple_platform: Module initialized\n");
    return 0;
}

/* 模块退出 */
static void __exit simple_platform_exit_module(void)
{
    /* 注销平台驱动 */
    platform_driver_unregister(&simple_platform_driver);

    /* 注销平台设备 */
    platform_device_unregister(&simple_platform_device);

    printk(KERN_INFO "simple_platform: Module exited\n");
}

module_init(simple_platform_init_module);
module_exit(simple_platform_exit_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple platform device driver");
```

## 6. 实践示例：USB设备驱动

### 6.1 USB驱动基础

```c
/* USB设备结构 */
struct usb_device {
    int devnum;                 /* 设备号 */
    char devpath[16];           /* 设备路径 */
    u32 route;                  /* 路由 */
    enum usb_device_state state; /* 设备状态 */
    enum usb_device_speed speed; /* 设备速度 */

    struct usb_device *parent;   /* 父设备 */
    struct usb_bus *bus;        /* USB总线 */
    struct usb_host_endpoint ep0; /* 端点0 */
    struct kref kref;           /* 引用计数 */

    u8 portnum;                 /* 端口号 */
    u8 level;                   /* 层级 */
    unsigned short bus_mA;      /* 总线电流 */
    u8 portnum;                 /* 端口号 */
    u8 level;                   /* 层级 */

    /* 描述符 */
    struct usb_device_descriptor descriptor; /* 设备描述符 */
    struct usb_host_config *config; /* 配置 */
    struct usb_host_config *actconfig; /* 活动配置 */
    struct usb_host_endpoint *ep_in[16]; /* 输入端点 */
    struct usb_host_endpoint *ep_out[16]; /* 输出端点 */

    /* 设备驱动 */
    char *serial;               /* 序列号 */
    char *product;               /* 产品名称 */
    char *manufacturer;          /* 制造商名称 */

    /* 电源管理 */
    int pm_usage_cnt;           /* 电源使用计数 */
    u32 quirks;                 /* 设备特性 */
    u32 persist_enabled:1;      /* 持续启用 */
    u32 have_langid:1;          /* 有语言ID */
    u32 authorized:1;           /* 已授权 */
    u32 authenticated:1;        /* 已认证 */
    u32 wusb:1;                 /* 无线USB */
    u32 lpm_capable:1;          /* LPM能力 */
    u32 usb2_hw_lpm_capable:1;  /* USB2硬件LPM能力 */
    u32 usb2_hw_lpm_besl_capable:1; /* USB2硬件LPM BESL能力 */
    u32 usb3_lpm_u1_enabled:1;  /* USB3 LPM U1启用 */
    u32 usb3_lpm_u2_enabled:1;  /* USB3 LPM U2启用 */
};

/* USB驱动结构 */
struct usb_driver {
    const char *name;           /* 驱动名称 */
    int (*probe)(struct usb_interface *intf,
             const struct usb_device_id *id); /* 探测函数 */
    void (*disconnect)(struct usb_interface *intf); /* 断开函数 */
    int (*unlocked_ioctl)(struct usb_interface *intf, unsigned int code,
            void *buf); /* 解锁IOCTL */
    int (*suspend)(struct usb_interface *intf, pm_message_t message); /* 挂起函数 */
    int (*resume)(struct usb_interface *intf); /* 恢复函数 */
    int (*reset_resume)(struct usb_interface *intf); /* 重置恢复函数 */
    int (*pre_reset)(struct usb_interface *intf); /* 预重置函数 */
    int (*post_reset)(struct usb_interface *intf); /* 重置后函数 */

    /* 驱动信息 */
    const struct usb_device_id *id_table; /* ID表 */
    const struct usb_device_id *dynamic_id; /* 动态ID */
    struct usb_dynids dynids;   /* 动态ID */
    struct usbdrv_wrap drvwrap; /* 驱动包装 */
    unsigned int no_dynamic_id:1; /* 无动态ID */
    unsigned int supports_autosuspend:1; /* 支持自动挂起 */
    unsigned int disable_hub_initiated_lpm:1; /* 禁用集线器发起的LPM */
    unsigned int soft_unbind:1; /* 软解绑 */
};

/* USB接口结构 */
struct usb_interface {
    struct usb_host_interface *altsetting; /* 交替设置 */
    struct usb_host_interface *cur_altsetting; /* 当前交替设置 */
    unsigned num_altsetting;    /* 交替设置数量 */
    struct usb_interface_assoc_descriptor *intf_assoc; /* 接口关联描述符 */
    int minor;                  /* 次设备号 */
    enum usb_interface_condition condition; /* 接口条件 */
    unsigned char sysfs_files_created:1; /* sysfs文件已创建 */
    unsigned char ep_devs_created:1; /* 端点设备已创建 */
    unsigned char unregistering:1; /* 正在注销 */
    unsigned char needs_remote_wakeup:1; /* 需要远程唤醒 */
    unsigned char needs_altsetting0:1; /* 需要交替设置0 */
    unsigned char needs_binding:1; /* 需要绑定 */
    unsigned char reset_running:1; /* 重置运行中 */
    unsigned char resetting_device:1; /* 重置设备中 */

    /* 设备驱动 */
    struct device dev;          /* 设备结构 */
    struct device_driver *driver; /* 设备驱动 */
    struct usb_driver *usb_driver; /* USB驱动 */
    void *private_data;         /* 私有数据 */
};
```

### 6.2 USB驱动实现

```c
/* 简单USB驱动示例 */
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/slab.h>

#define USB_VENDOR_ID 0x1234      /* 示例厂商ID */
#define USB_PRODUCT_ID 0x5678     /* 示例产品ID */
#define DRIVER_NAME "simple_usb"

/* USB接口结构 */
struct simple_usb_interface {
    struct usb_device *udev;     /* USB设备 */
    struct usb_interface *intf;  /* USB接口 */
    struct urb *urb;             /* URB */
    unsigned char *bulk_in_buffer; /* 批量输入缓冲区 */
    size_t bulk_in_size;         /* 批量输入大小 */
    __u8 bulk_in_endpointAddr;   /* 批量输入端点地址 */
    __u8 bulk_out_endpointAddr;  /* 批量输出端点地址 */
    struct kref kref;             /* 引用计数 */
};

/* USB设备ID表 */
static const struct usb_device_id simple_usb_table[] = {
    { USB_DEVICE(USB_VENDOR_ID, USB_PRODUCT_ID) },
    {} /* 终止条目 */
};
MODULE_DEVICE_TABLE(usb, simple_usb_table);

/* 释放接口 */
static void simple_usb_delete(struct kref *kref)
{
    struct simple_usb_interface *data = container_of(kref,
                   struct simple_usb_interface, kref);

    /* 释放URB */
    if (data->urb) {
        usb_kill_urb(data->urb);
        usb_free_urb(data->urb);
    }

    /* 释放缓冲区 */
    if (data->bulk_in_buffer)
        kfree(data->bulk_in_buffer);

    /* 释放接口 */
    kfree(data);
}

/* URB完成回调函数 */
static void simple_usb_read_bulk_callback(struct urb *urb)
{
    struct simple_usb_interface *data = urb->context;
    int status = urb->status;

    /* 检查URB状态 */
    if (status) {
        if (!(status == -ENOENT || status == -ECONNRESET ||
              status == -ESHUTDOWN))
            printk(KERN_ERR "simple_usb: URB failed with status %d\n", status);
        return;
    }

    /* 处理接收到的数据 */
    if (urb->actual_length > 0) {
        printk(KERN_INFO "simple_usb: Received %d bytes\n", urb->actual_length);
        /* 这里可以处理接收到的数据 */
    }

    /* 重新提交URB */
    usb_submit_urb(data->urb, GFP_ATOMIC);
}

/* 打开设备 */
static int simple_usb_open(struct inode *inode, struct file *file)
{
    struct simple_usb_interface *data;
    struct usb_interface *intf;
    int subminor;
    int error = 0;

    /* 获取次设备号 */
    subminor = iminor(inode);

    /* 获取USB接口 */
    intf = usb_find_interface(&simple_usb_driver, subminor);
    if (!intf) {
        printk(KERN_ERR "simple_usb: Can't find device for minor %d\n", subminor);
        return -ENODEV;
    }

    /* 获取接口数据 */
    data = usb_get_intfdata(intf);
    if (!data) {
        error = -ENODEV;
        goto exit;
    }

    /* 增加引用计数 */
    kref_get(&data->kref);

    /* 保存数据到文件 */
    file->private_data = data;

exit:
    return error;
}

/* 关闭设备 */
static int simple_usb_release(struct inode *inode, struct file *file)
{
    struct simple_usb_interface *data;

    data = file->private_data;
    if (data) {
        /* 减少引用计数 */
        kref_put(&data->kref, simple_usb_delete);
    }

    return 0;
}

/* 读取数据 */
static ssize_t simple_usb_read(struct file *file, char __user *buffer,
                  size_t count, loff_t *ppos)
{
    struct simple_usb_interface *data;
    int error = 0;

    data = file->private_data;
    if (!data) {
        printk(KERN_ERR "simple_usb: No device data\n");
        return -ENODEV;
    }

    /* 这里可以实现具体的读取逻辑 */
    /* 例如，从接收缓冲区复制数据到用户空间 */

    return error;
}

/* 写入数据 */
static ssize_t simple_usb_write(struct file *file, const char __user *buffer,
                   size_t count, loff_t *ppos)
{
    struct simple_usb_interface *data;
    int bytes_written = 0;
    int error = 0;

    data = file->private_data;
    if (!data) {
        printk(KERN_ERR "simple_usb: No device data\n");
        return -ENODEV;
    }

    /* 分配URB */
    struct urb *urb = usb_alloc_urb(0, GFP_KERNEL);
    if (!urb) {
        error = -ENOMEM;
        goto exit;
    }

    /* 分配传输缓冲区 */
    unsigned char *transfer_buffer = kmalloc(count, GFP_KERNEL);
    if (!transfer_buffer) {
        error = -ENOMEM;
        goto free_urb;
    }

    /* 从用户空间复制数据 */
    if (copy_from_user(transfer_buffer, buffer, count)) {
        error = -EFAULT;
        goto free_buffer;
    }

    /* 填充URB */
    usb_fill_bulk_urb(urb, data->udev,
             usb_sndbulkpipe(data->udev, data->bulk_out_endpointAddr),
             transfer_buffer, count,
             simple_usb_write_bulk_callback, data);

    /* 提交URB */
    error = usb_submit_urb(urb, GFP_KERNEL);
    if (error) {
        printk(KERN_ERR "simple_usb: Failed to submit URB: %d\n", error);
        goto free_buffer;
    }

    bytes_written = count;

free_buffer:
    kfree(transfer_buffer);
free_urb:
    usb_free_urb(urb);
exit:
    return error ? error : bytes_written;
}

/* 写入URB完成回调函数 */
static void simple_usb_write_bulk_callback(struct urb *urb)
{
    struct simple_usb_interface *data = urb->context;
    int status = urb->status;

    /* 检查URB状态 */
    if (status) {
        if (!(status == -ENOENT || status == -ECONNRESET ||
              status == -ESHUTDOWN))
            printk(KERN_ERR "simple_usb: Write URB failed with status %d\n", status);
        return;
    }

    /* 写入完成 */
    printk(KERN_INFO "simple_usb: Wrote %d bytes\n", urb->actual_length);
}

/* 文件操作 */
static const struct file_operations simple_usb_fops = {
    .owner = THIS_MODULE,
    .open = simple_usb_open,
    .release = simple_usb_release,
    .read = simple_usb_read,
    .write = simple_usb_write,
    .llseek = no_llseek,
};

/* USB驱动 */
static struct usb_driver simple_usb_driver = {
    .name = DRIVER_NAME,
    .probe = simple_usb_probe,
    .disconnect = simple_usb_disconnect,
    .fops = &simple_usb_fops,
    .id_table = simple_usb_table,
};

/* USB驱动探测函数 */
static int simple_usb_probe(struct usb_interface *intf,
               const struct usb_device_id *id)
{
    struct simple_usb_interface *data;
    struct usb_host_interface *iface_desc;
    struct usb_endpoint_descriptor *endpoint;
    int i;
    int error = -ENOMEM;

    /* 分配接口数据 */
    data = kzalloc(sizeof(struct simple_usb_interface), GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "simple_usb: Out of memory\n");
        return error;
    }

    /* 初始化引用计数 */
    kref_init(&data->kref);

    /* 保存设备和接口 */
    data->udev = usb_get_dev(interface_to_usbdev(intf));
    data->intf = intf;

    /* 设置接口数据 */
    usb_set_intfdata(intf, data);

    /* 获取接口描述符 */
    iface_desc = intf->cur_altsetting;

    /* 查找批量输入端点 */
    for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
        endpoint = &iface_desc->endpoint[i].desc;

        if (usb_endpoint_is_bulk_in(endpoint)) {
            data->bulk_in_size = usb_endpoint_maxp(endpoint);
            data->bulk_in_endpointAddr = endpoint->bEndpointAddress;
            data->bulk_in_buffer = kmalloc(data->bulk_in_size, GFP_KERNEL);
            if (!data->bulk_in_buffer) {
                printk(KERN_ERR "simple_usb: Could not allocate bulk_in_buffer\n");
                goto error;
            }
        }

        if (usb_endpoint_is_bulk_out(endpoint)) {
            data->bulk_out_endpointAddr = endpoint->bEndpointAddress;
        }
    }

    /* 检查是否找到必要的端点 */
    if (!(data->bulk_in_endpointAddr && data->bulk_out_endpointAddr)) {
        printk(KERN_ERR "simple_usb: Could not find both bulk-in and bulk-out endpoints\n");
        error = -ENODEV;
        goto error;
    }

    /* 分配URB */
    data->urb = usb_alloc_urb(0, GFP_KERNEL);
    if (!data->urb) {
        printk(KERN_ERR "simple_usb: Could not allocate URB\n");
        error = -ENOMEM;
        goto error;
    }

    /* 填充URB */
    usb_fill_bulk_urb(data->urb, data->udev,
             usb_rcvbulkpipe(data->udev, data->bulk_in_endpointAddr),
             data->bulk_in_buffer, data->bulk_in_size,
             simple_usb_read_bulk_callback, data);

    /* 提交URB */
    error = usb_submit_urb(data->urb, GFP_KERNEL);
    if (error) {
        printk(KERN_ERR "simple_usb: Failed to submit URB: %d\n", error);
        goto error;
    }

    printk(KERN_INFO "simple_usb: USB device probed\n");
    printk(KERN_INFO "simple_usb: Vendor ID: 0x%04x\n", id->idVendor);
    printk(KERN_INFO "simple_usb: Product ID: 0x%04x\n", id->idProduct);

    return 0;

error:
    simple_usb_delete(&data->kref);
    return error;
}

/* USB驱动断开函数 */
static void simple_usb_disconnect(struct usb_interface *intf)
{
    struct simple_usb_interface *data;

    /* 获取接口数据 */
    data = usb_get_intfdata(intf);

    /* 清除接口数据 */
    usb_set_intfdata(intf, NULL);

    /* 减少引用计数 */
    kref_put(&data->kref, simple_usb_delete);

    printk(KERN_INFO "simple_usb: USB device disconnected\n");
}

/* 模块初始化 */
static int __init simple_usb_init(void)
{
    int error;

    /* 注册USB驱动 */
    error = usb_register(&simple_usb_driver);
    if (error) {
        printk(KERN_ERR "simple_usb: Failed to register USB driver\n");
        return error;
    }

    printk(KERN_INFO "simple_usb: USB driver registered\n");
    return 0;
}

/* 模块退出 */
static void __exit simple_usb_exit(void)
{
    /* 注销USB驱动 */
    usb_deregister(&simple_usb_driver);

    printk(KERN_INFO "simple_usb: USB driver unregistered\n");
}

module_init(simple_usb_init);
module_exit(simple_usb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple USB device driver");
```

## 7. 调试和监控

### 7.1 设备驱动调试工具

```c
/* 调试信息 */
/proc/devices:
Character devices:
  1 mem
  4 /dev/vc/0
  5 /dev/tty
  7 vcs
  10 misc
  13 input
  21 sg
  29 fb
  81 simple_char          # 自定义字符设备

Block devices:
  7 loop
  8 sd
  11 sr
  65 sd
  66 sd
  67 sd
  68 sd
  69 sd
  70 sd
  71 sd
 128 sd
  129 sd
  130 sd
  131 sd
  132 sd
  133 sd
  134 sd
  135 sd
  253 simple_blk          # 自定义块设备

/* sysfs设备信息 */
/sys/devices:
├── simple_char
│   ├── dev
│   ├── device
│   ├── power
│   ├── subsystem
│   └── uevent
├── simple_blk
│   ├── dev
│   ├── device
│   ├── power
│   ├── subsystem
│   └── uevent
└── simple_net
    ├── device
    ├── ifindex
    ├── net:eth0
    ├── power
    ├── subsystem
    └── uevent
```

### 7.2 性能监控

```c
/* 网络设备统计 */
/proc/net/dev:
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 2776740   21253    0    0    0     0          0         0  2776740   21253    0    0    0     0       0          0
  eth0: 1234567   12345    0    0    0     0          0         0  7654321   23456    0    0    0     0       0          0

/* 块设备统计 */
/proc/diskstats:
   8       0 sda 12345 0 67890 9876 54321 0 87654 5432 0 12345 76543
   8      16 sdb 0 0 0 0 0 0 0 0 0 0 0
 253      0 simple_blk 1000 0 2000 100 3000 0 4000 200 0 0 0

/* 中断统计 */
/proc/interrupts:
           CPU0       CPU1
  0:         10          5   IO-APIC-edge      timer
  1:       1000        800   IO-APIC-edge      i8042
  8:          0          0   IO-APIC-edge      rtc0
  9:        500        400   IO-APIC-fasteoi   acpi
 16:       2000       1500   IO-APIC-fasteoi   simple_net  # 网络设备中断
```

## 8. 性能优化建议

### 8.1 字符设备优化
- 使用零拷贝技术减少数据复制
- 优化缓冲区大小和数量
- 使用异步IO提高并发性能
- 合理设置设备权限和访问模式

### 8.2 块设备优化
- 调整请求队列参数
- 使用多队列块设备(MQ)
- 优化I/O调度器选择
- 启用写入缓存和预读

### 8.3 网络设备优化
- 使用NAPI减少中断开销
- 启用RSS和LRO功能
- 优化缓冲区管理
- 使用DMA和零拷贝技术

### 8.4 通用优化
- 合理使用内存和DMA
- 优化中断处理函数
- 使用锁优化并发访问
- 考虑NUMA架构优化

## 9. 总结

Linux设备驱动子系统是一个功能强大且灵活的框架，支持多种设备类型和复杂的硬件交互。通过深入理解字符设备、块设备、网络设备驱动和设备模型，我们可以开发高效、稳定的设备驱动程序。

**关键要点：**
1. 设备驱动采用分层架构设计
2. 支持字符设备、块设备、网络设备等多种类型
3. sysfs提供设备管理和调试接口
4. 平台设备和USB设备提供标准化的驱动框架
5. 性能优化需要考虑并发、DMA、中断等因素

通过本章的学习，你将具备深入理解Linux设备驱动的能力，为进一步的硬件驱动开发打下坚实基础。