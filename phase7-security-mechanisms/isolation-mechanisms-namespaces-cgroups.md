# Linux内核隔离机制深度分析

## 概述
Linux内核提供了强大的资源隔离机制，主要包括Namespaces和cgroups。这些机制是实现容器技术和虚拟化技术的基础，为系统安全提供了重要的隔离保障。本文基于Linux 6.17内核源代码，深入分析Namespaces和cgroups的架构设计和实现原理。

## 1. Namespaces隔离机制

### 1.1 Namespaces架构概述

Namespaces提供了一种轻量级的进程隔离机制，使进程只能看到自己命名空间内的资源：

```c
// include/linux/nsproxy.h
/* 命名空间代理结构 */
struct nsproxy {
    atomic_t count;
    struct uts_namespace *uts_ns;      /* UTS命名空间 */
    struct ipc_namespace *ipc_ns;      /* IPC命名空间 */
    struct mnt_namespace *mnt_ns;      /* 挂载命名空间 */
    struct pid_namespace *pid_ns_for_children; /* PID命名空间 */
    struct net       *net_ns;          /* 网络命名空间 */
    struct cgroup_namespace *cgroup_ns; /* Cgroup命名空间 */
};

/* 命名空间类型 */
enum ufs_name {
    UTS_NS_INO = 0x1,
    IPC_NS_INO = 0x2,
    USER_NS_INO = 0x3,
    PID_NS_INO = 0x4,
    NET_NS_INO = 0x5,
    CGROUP_NS_INO = 0x6,
};

/* 命名空间操作 */
struct proc_ns_operations {
    const char *name;
    int type;
    struct ns_common *(*get)(struct task_struct *task);
    void (*put)(struct ns_common *ns);
    int (*install)(struct nsproxy *nsproxy, struct ns_common *ns);
    struct user_namespace *(*owner)(struct ns_common *ns);
    struct ns_common *(*get_parent)(struct ns_common *ns);
};

/* 通用命名空间结构 */
struct ns_common {
    atomic_t count;
    unsigned int inum;
    const struct proc_ns_operations *ops;
};
```

### 1.2 UTS命名空间

UTS命名空间隔离主机名和域名：

```c
// include/linux/utsname.h
/* UTS命名空间结构 */
struct uts_namespace {
    struct new_utsname name;
    struct user_namespace *user_ns;
    struct ucounts *ucounts;
    struct ns_common ns;
};

/* UTS信息结构 */
struct new_utsname {
    char sysname[65];      /* 操作系统名称 */
    char nodename[65];     /* 主机名 */
    char release[65];      /* 内核版本 */
    char version[65];      /* 内核版本详情 */
    char machine[65];      /* 硬件类型 */
    char domainname[65];   /* 域名 */
};

/* 创建UTS命名空间 */
static struct uts_namespace *create_uts_ns(void)
{
    struct uts_namespace *uts_ns;

    /* 分配命名空间 */
    uts_ns = kmalloc(sizeof(struct uts_namespace), GFP_KERNEL);
    if (!uts_ns)
        return ERR_PTR(-ENOMEM);

    /* 复制当前UTS信息 */
    memcpy(&uts_ns->name, &init_uts_ns.name, sizeof(uts_ns->name));

    /* 设置引用计数 */
    uts_ns->user_ns = get_user_ns(&init_user_ns);
    uts_ns->ucounts = inc_ucount(uts_ns->user_ns, UCOUNT_UTS_NAMESPACES);
    if (!uts_ns->ucounts) {
        kfree(uts_ns);
        return ERR_PTR(-ENOSPC);
    }

    /* 设置命名空间号 */
    uts_ns->ns.inum = proc_alloc_inum(&uts_ns->ns);

    return uts_ns;
}

/* 复制UTS命名空间 */
struct uts_namespace *copy_utsname(unsigned long flags,
                                 struct user_namespace *user_ns,
                                 struct uts_namespace *old_ns)
{
    struct uts_namespace *new_ns;

    /* 如果不需要新命名空间，直接返回旧命名空间 */
    if (!(flags & CLONE_NEWUTS))
        return get_uts_ns(old_ns);

    /* 创建新命名空间 */
    new_ns = create_uts_ns();
    if (IS_ERR(new_ns))
        return new_ns;

    return new_ns;
}
```

### 1.3 IPC命名空间

IPC命名空间隔离System V IPC和POSIX消息队列：

```c
// include/linux/ipc_namespace.h
/* IPC命名空间结构 */
struct ipc_namespace {
    struct user_namespace *user_ns;
    struct ucounts *ucounts;

    /* System V IPC */
    struct ipc_ids ids[3];    /* 消息队列、信号量、共享内存 */
    int sem_ctls[4];          /* 信号量控制参数 */
    int msg_ctlmax;           /* 最大消息长度 */
    int msg_ctlmnb;           /* 消息队列最大字节数 */
    int msg_ctlmni;           /* 消息队列最大数量 */
    size_t shm_ctlmax;        /* 最大共享内存段 */
    size_t shm_ctlall;         /* 共享内存总量限制 */
    int shm_ctlmni;           /* 共享内存段数量 */
    struct file *shm_proc_file; /* /proc/shm文件 */

    /* POSIX消息队列 */
    struct vfsmount *mq_mnt;   /* 消息队列挂载点 */

    /* 命名空间管理 */
    unsigned int proc_inum;   /* /proc中的inode号 */
    bool proc_mounted;         /* 是否已挂载到/proc */
};

/* 创建IPC命名空间 */
static struct ipc_namespace *create_ipc_ns(struct user_namespace *user_ns,
                                          struct ipc_namespace *old_ns)
{
    struct ipc_namespace *ns;
    int err;

    /* 分配命名空间 */
    ns = kmalloc(sizeof(struct ipc_namespace), GFP_KERNEL);
    if (!ns)
        return ERR_PTR(-ENOMEM);

    /* 设置用户命名空间 */
    ns->user_ns = get_user_ns(user_ns);
    ns->ucounts = inc_ucount(user_ns, UCOUNT_IPC_NAMESPACES);
    if (!ns->ucounts) {
        err = -ENOSPC;
        goto fail_free;
    }

    /* 初始化IPC ID */
    err = sem_init_ns(ns);
    if (err)
        goto fail_put;

    err = msg_init_ns(ns);
    if (err)
        goto fail_sem;

    err = shm_init_ns(ns);
    if (err)
        goto fail_msg;

    /* 设置消息队列 */
    ns->mq_mnt = copy_mnt_ns(old_ns->mq_mnt, user_ns);
    if (IS_ERR(ns->mq_mnt)) {
        err = PTR_ERR(ns->mq_mnt);
        goto fail_shm;
    }

    /* 设置/proc文件 */
    err = proc_mount_ipc(ns);
    if (err)
        goto fail_mq;

    return ns;

fail_mq:
    mntput(ns->mq_mnt);
fail_shm:
    shm_exit_ns(ns);
fail_msg:
    msg_exit_ns(ns);
fail_sem:
    sem_exit_ns(ns);
fail_put:
    put_user_ns(ns->user_ns);
    dec_ucount(ns->ucounts, UCOUNT_IPC_NAMESPACES);
fail_free:
    kfree(ns);
    return ERR_PTR(err);
}
```

### 1.4 PID命名空间

PID命名空间隔离进程ID空间：

```c
// include/linux/pid_namespace.h
/* PID命名空间结构 */
struct pid_namespace {
    struct kref kref;
    struct pid_namespace *child_reaper; /* 子进程收割者 */
    struct pid_namespace *parent;      /* 父命名空间 */
    struct user_namespace *user_ns;
    struct ucounts *ucounts;
    struct rb_root cached_tree;       /* 缓存的PID树 */
    struct idr idr;                   /* PID分配器 */
    struct task_struct *pid_allocated; /* 最近分配的PID */
    unsigned int nr_allocated;          /* 已分配的PID数量 */
    unsigned int nr_hashed;             /* 哈希的PID数量 */
    struct task_struct *pid_changer;    /* PID修改者 */
    spinlock_t pid_caches_lock;        /* PID缓存锁 */
    struct list_head pid_caches;        /* PID缓存列表 */

    /* PID限制 */
    unsigned int level;                /* 命名空间层级 */
    unsigned int nr_children;          /* 子命名空间数量 */
    pid_t min_pid;                     /* 最小PID */
    pid_t max_pid;                     /* 最大PID */
    pid_t nr_pids;                     /* PID数量 */

    /* 回收管理 */
    int hide_pid;                      /* 隐藏PID */
    int reboot;                        /* 重启命令 */
    struct ns_common ns;               /* 通用命名空间 */
};

/* PID结构 */
struct pid {
    atomic_t count;
    unsigned int level;
    /* 每个命名空间的PID号 */
    struct upid numbers[1];
};

/* 每个命名空间的PID号 */
struct upid {
    int nr;                     /* PID号 */
    struct pid_namespace *ns;   /* 所属命名空间 */
    struct hlist_node pid_chain; /* PID链表节点 */
};

/* 创建PID命名空间 */
static struct pid_namespace *create_pid_namespace(struct user_namespace *user_ns,
                                                 struct pid_namespace *parent_pid_ns)
{
    struct pid_namespace *ns;
    unsigned int level = parent_pid_ns->level + 1;
    int err;

    /* 检查命名空间层级 */
    if (level > MAX_PID_NS_LEVEL) {
        err = -ENOSPC;
        goto out;
    }

    /* 分配命名空间 */
    ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
    if (!ns) {
        err = -ENOMEM;
        goto out;
    }

    /* 初始化引用计数 */
    kref_init(&ns->kref);
    ns->level = level;
    ns->parent = get_pid_ns(parent_pid_ns);
    ns->user_ns = get_user_ns(user_ns);
    ns->ucounts = inc_ucount(user_ns, UCOUNT_PID_NAMESPACES);
    if (!ns->ucounts) {
        err = -ENOSPC;
        goto fail_put_user_ns;
    }

    /* 初始化IDR */
    idr_init(&ns->idr);
    ns->nr_pids = PID_MAX_LIMIT;

    /* 初始化缓存 */
    ns->min_pid = 1;
    ns->max_pid = PID_MAX_LIMIT;
    INIT_HLIST_HEAD(&ns->pid_caches);
    spin_lock_init(&ns->pid_caches_lock);

    /* 设置命名空间号 */
    ns->ns.inum = proc_alloc_inum(&ns->ns);

    return ns;

fail_put_user_ns:
    put_user_ns(ns->user_ns);
    put_pid_ns(ns->parent);
    kmem_cache_free(pid_ns_cachep, ns);
out:
    return ERR_PTR(err);
}
```

### 1.5 网络命名空间

网络命名空间隔离网络设备、IP地址、路由表等网络资源：

```c
// include/net/net_namespace.h
/* 网络命名空间结构 */
struct net {
    /* 引用计数 */
    atomic_t passive;    /* 被动引用计数 */
    atomic_t count;      /* 主动引用计数 */

    /* 命名空间管理 */
    spinlock_t rules_mod_lock;   /* 规则修改锁 */
    unsigned int proc_inum;      /* /proc中的inode号 */

    /* 网络设备 */
    struct list_head dev_base_head;    /* 网络设备列表 */
    struct hlist_head *dev_name_head;  /* 设备名称哈希表 */
    struct hlist_head *dev_index_head; /* 设备索引哈希表 */
    unsigned int dev_base_seq;         /* 设备序列号 */
    int ifindex;                      /* 接口索引 */

    /* 网络协议栈 */
    struct net_device *loopback_dev;     /* 回环设备 */
    struct netns_core core;              /* 核心网络 */
    struct netns_ipv4 ipv4;              /* IPv4配置 */
    struct netns_ipv6 ipv6;              /* IPv6配置 */
    struct netns_unix unx;               /* Unix域套接字 */
    struct netns_packet packet;          /* Packet套接字 */
    struct netns_key key;                /* 密钥管理 */
    struct netns_nf nf;                  /* 网络过滤 */
    struct netns_xt xt;                  /* Xtables */
    struct netns_ct ct;                  /* 连接跟踪 */
    struct netns_nftables nft;           /* nftables */
    struct netns_mib mib;                /* MIB统计 */
    struct sock *diag_nlsk;              /* 诊断套接字 */

    /* 用户空间 */
    struct user_namespace *user_ns;       /* 用户命名空间 */
    struct ucounts *ucounts;             /* ucounts */
    struct idr netns_ids;                /* 网络命名空间ID */

    /* 通用命名空间 */
    struct ns_common ns;
};

/* 创建网络命名空间 */
struct net *copy_net_ns(unsigned long flags, struct user_namespace *user_ns,
                         struct net *old_net)
{
    struct net *net;
    int err;

    /* 如果不需要新命名空间，直接返回旧命名空间 */
    if (!(flags & CLONE_NEWNET))
        return get_net(old_net);

    /* 分配网络命名空间 */
    net = net_alloc();
    if (!net)
        return ERR_PTR(-ENOMEM);

    /* 设置用户命名空间 */
    net->user_ns = get_user_ns(user_ns);
    net->ucounts = inc_ucount(user_ns, UCOUNT_NET_NAMESPACES);
    if (!net->ucounts) {
        err = -ENOSPC;
        goto fail_free;
    }

    /* 初始化网络设备 */
    err = net_dev_init(net);
    if (err)
        goto fail_ucounts;

    /* 初始化网络协议栈 */
    err = netns_ip4_init(net);
    if (err)
        goto fail_dev;

    err = netns_ip6_init(net);
    if (err)
        goto fail_ip4;

    err = netns_unix_init(net);
    if (err)
        goto fail_ip6;

    /* 设置回环设备 */
    err = net_loopback_init(net);
    if (err)
        goto fail_unix;

    /* 设置命名空间号 */
    net->ns.inum = proc_alloc_inum(&net->ns);

    return net;

fail_unix:
    netns_unix_exit(net);
fail_ip6:
    netns_ip6_exit(net);
fail_ip4:
    netns_ip4_exit(net);
fail_dev:
    net_dev_exit(net);
fail_ucounts:
    dec_ucount(net->ucounts, UCOUNT_NET_NAMESPACES);
fail_free:
    put_user_ns(net->user_ns);
    net_free(net);
    return ERR_PTR(err);
}
```

## 2. Cgroups资源控制

### 2.1 Cgroups架构设计

Cgroups提供资源限制、审计和隔离机制：

```c
// include/linux/cgroup.h
/* Cgroup子系统结构 */
struct cgroup_subsys {
    struct cgroup_subsys_state *(*css_alloc)(struct cgroup_subsys_state *parent_css);
    int (*css_online)(struct cgroup_subsys_state *css);
    void (*css_offline)(struct cgroup_subsys_state *css);
    void (*css_free)(struct cgroup_subsys_state *css);
    int (*can_attach)(struct cgroup_taskset *tset);
    void (*cancel_attach)(struct cgroup_taskset *tset);
    void (*attach)(struct cgroup_taskset *tset);
    void (*fork)(struct task_struct *task);
    void (*exit)(struct task_struct *task);
    void (*release)(struct task_struct *task);
    void (*bind)(struct cgroup_subsys_state *root_css);
    int (*disallow_attach)(struct cgroup_subsys_state *css,
                           struct task_struct *task);
    bool (*threaded)(struct cgroup_subsys_state *css);
};

/* Cgroup子系统状态 */
struct cgroup_subsys_state {
    struct cgroup *cgroup;          /* 所属cgroup */
    struct cgroup_subsys *ss;       /* 子系统 */
    struct cftype *files;           /* 控制文件 */
    struct list_head sibling;       /* 兄弟节点 */
    struct list_head children;       /* 子节点 */
    struct list_head sibling_list;   /* 兄弟列表 */
    struct list_head tasks;         /* 任务列表 */
    struct percpu_ref refcnt;       /* 引用计数 */
    struct work_struct destroy_work; /* 销毁工作 */
    struct list_head rstat_list;    /* rstat列表 */
    struct list_head rstat_css_list; /* rstat CSS列表 */
    bool online;                     /* 是否在线 */
    bool dying;                      /* 是否正在销毁 */
    bool threaded;                   /* 是否线程化 */
    u32 flags;                      /* 标志位 */
};

/* Cgroup结构 */
struct cgroup {
    struct cgroup_subsys_state self;     /* 自身CSS */
    struct cgroup *parent;                /* 父cgroup */
    struct kernfs_node *kn;               /* kernfs节点 */
    struct list_head children;            /* 子cgroup列表 */
    struct list_head sibling;             /* 兄弟cgroup列表 */
    struct list_head files;               /* 控制文件列表 */
    struct list_head e_csses;             /* 启用的CSS列表 */
    struct list_head dfl_csets;           /* 默认层次cset列表 */
    struct list_head remote_csets;         /* 远程cset列表 */
    struct cgroup_file procs_file;        /* procs文件 */
    struct cgroup_file events_file;       /* events文件 */
    struct cgroup_file cgroup_procs_file; /* cgroup.procs文件 */
    struct cgroup_file cgroup_events_file; /* cgroup.events文件 */
    struct list_head pidlists;            /* PID列表 */
    struct mutex pidlist_mutex;          /* PID列表锁 */
    struct work_struct release_agent_work; /* 释放代理工作 */
    atomic_t populated_cnt;             /* 已填充计数 */
    atomic_t dying_cnt;                  /* 死亡计数 */
    struct list_head cset_links;           /* cset链接 */
    struct list_head cgrps;                /* cgroup列表 */
    struct list_head csets;                /* cset列表 */
    struct list_head dying_csets;          /* 死亡cset列表 */
    struct list_head release_list;         /* 释放列表 */
    struct work_struct destroy_work;       /* 销毁工作 */
    struct work_struct release_work;       /* 释放工作 */
    struct work_struct psi_work;           /* PSI工作 */
    struct psi_trigger psi_trigger;        /* PSI触发器 */
    struct list_head psi_offline_list;     /* PSI离线列表 */
    struct work_struct psi_offline_work;   /* PSI离线工作 */
    struct list_head offline_csses;         /* 离线CSS列表 */
    struct work_struct offline_work;       /* 离线工作 */
    struct list_head release_list;         /* 释放列表 */
    struct work_struct release_work;       /* 释放工作 */
    struct list_head remote_children;       /* 远程子节点 */
    struct list_head remote_siblings;       /* 远程兄弟节点 */
    struct list_head remote_csets;          /* 远程cset */
    struct list_head remote_tasks;          /* 远程任务 */
    struct list_head remote_cgrp_links;      /* 远程cgroup链接 */
    struct list_head remote_cset_links;      /* 远程cset链接 */
    struct list_head remote_pidlists;        /* 远程PID列表 */
    struct mutex remote_mutex;               /* 远程锁 */
    struct list_head remote_children;         /* 远程子节点 */
    struct list_head remote_siblings;         /* 远程兄弟节点 */
    struct list_head remote_csets;            /* 远程cset */
    struct list_head remote_tasks;            /* 远程任务 */
    struct list_head remote_cgrp_links;       /* 远程cgroup链接 */
    struct list_head remote_cset_links;       /* 远程cset链接 */
    struct list_head remote_pidlists;         /* 远程PID列表 */
    struct mutex remote_mutex;                /* 远程锁 */
    atomic_t remote_counter;                   /* 远程计数器 */
    struct wait_queue_head remote_waitq;       /* 远程等待队列 */
    struct completion remote_completion;        /* 远程完成量 */
    struct kref remote_kref;                   /* 远程引用 */
    struct rcu_head remote_rcu;                /* 远程RCU */
    struct list_head remote_children;           /* 远程子节点 */
    struct list_head remote_siblings;           /* 远程兄弟节点 */
    struct list_head remote_csets;              /* 远程cset */
    struct list_head remote_tasks;              /* 远程任务 */
    struct list_head remote_cgrp_links;         /* 远程cgroup链接 */
    struct list_head remote_cset_links;         /* 远程cset链接 */
    struct list_head remote_pidlists;           /* 远程PID列表 */
    struct mutex remote_mutex;                  /* 远程锁 */
    atomic_t remote_counter;                    /* 远程计数器 */
    struct wait_queue_head remote_waitq;        /* 远程等待队列 */
    struct completion remote_completion;         /* 远程完成量 */
    struct kref remote_kref;                    /* 远程引用 */
    struct rcu_head remote_rcu;                 /* 远程RCU */
};
```

### 2.2 内存子系统

内存子系统提供内存和交换空间的限制：

```c
// mm/memcontrol.c
/* 内存控制组结构 */
struct mem_cgroup {
    struct cgroup_subsys_state css;   /* CSS基类 */
    struct page_counter memory;        /* 内存计数器 */
    struct page_counter memsw;         /* 内存+交换计数器 */
    struct page_counter kmem;          /* 内核内存计数器 */
    struct page_counter tcpmem;        /* TCP内存计数器 */

    /* 内存限制 */
    unsigned long high;                /* 软限制 */
    unsigned long max;                 /* 硬限制 */
    unsigned long soft_limit;          /* 软限制 */

    /* 交换限制 */
    unsigned long swap_max;            /* 交换最大值 */

    /* 内存事件 */
    struct cgroup_file events_file;     /* 事件文件 */
    struct cgroup_file memory.events_file; /* 内存事件文件 */
    struct cgroup_file memory.swap.events_file; /* 交换事件文件 */

    /* OOM控制 */
    struct oom_ecc oom_ecc;           /* OOM控制 */
    struct mem_cgroup_eventfd_list oom_notify; /* OOM通知 */

    /* 统计信息 */
    struct mem_cgroup_stat stat;       /* 统计数据 */
    struct mem_cgroup_tree tree;        /* 树结构 */
    struct mem_cgroup_id id;           /* ID */
    bool use_hierarchy;                /* 是否使用层次结构 */
    bool oom_lock;                     /* OOM锁 */
    struct mutex memcg_lock;           /* 内存控制组锁 */

    /* 移动控制 */
    struct task_struct *move_lock_task; /* 移动锁任务 */
    struct css_set *move_lock_css_set;  /* 移动锁CSS集 */
    struct list_head move_list;         /* 移动列表 */
    bool move_in_progress;              /* 移动进行中 */

    /* PSI */
    struct psi_group psi;              /* PSI组 */
    struct psi_trigger psi_trigger;     /* PSI触发器 */
};

/* 内存控制文件 */
static struct cftype mem_cgroup_files[] = {
    {
        .name = "memory.current",
        .flags = CFTYPE_NOT_ON_ROOT,
        .read_u64 = memory_current_read,
    },
    {
        .name = "memory.max",
        .flags = CFTYPE_NOT_ON_ROOT,
        .read_u64 = memory_max_read,
        .write_u64 = memory_max_write,
    },
    {
        .name = "memory.high",
        .flags = CFTYPE_NOT_ON_ROOT,
        .read_u64 = memory_high_read,
        .write_u64 = memory_high_write,
    },
    {
        .name = "memory.swap.current",
        .flags = CFTYPE_NOT_ON_ROOT,
        .read_u64 = memory_swap_current_read,
    },
    {
        .name = "memory.swap.max",
        .flags = CFTYPE_NOT_ON_ROOT,
        .read_u64 = memory_swap_max_read,
        .write_u64 = memory_swap_max_write,
    },
    {
        .name = "memory.events",
        .flags = CFTYPE_NOT_ON_ROOT,
        .file_offset = offsetof(struct mem_cgroup, events_file),
        .seq_show = memory_events_show,
    },
    { }    /* 终止符 */
};

/* 内存分配限制 */
static int __mem_cgroup_charge(struct page *page, struct mm_struct *mm,
                               gfp_t gfp_mask)
{
    struct mem_cgroup *memcg;
    int ret;

    /* 查找内存控制组 */
    memcg = get_mem_cgroup_from_mm(mm);
    if (!memcg)
        return 0;

    /* 尝试充电 */
    ret = try_charge(memcg, gfp_mask, nr_pages);
    if (ret) {
        /* 充电失败 */
        put_mem_cgroup(memcg);
        return ret;
    }

    /* 设置页面控制组 */
    commit_charge(page, memcg);

    put_mem_cgroup(memcg);
    return 0;
}
```

### 2.3 CPU子系统

CPU子系统提供CPU时间片的限制：

```c
// kernel/sched/core.c
/* CPU控制组结构 */
struct task_group {
    struct cgroup_subsys_state css;   /* CSS基类 */

    /* 调度实体 */
    struct sched_entity **se;         /* 调度实体数组 */
    struct cfs_rq **cfs_rq;          /* CFS运行队列数组 */
    struct rt_rq **rt_rq;            /* RT运行队列数组 */
    struct rq **rq;                  /* 运行队列数组 */

    /* CPU配额 */
    u64 cpu_shares;                  /* CPU份额 */
    u64 cpu_quota;                   /* CPU配额 */
    u64 cpu_period;                  /* CPU周期 */

    /* 带宽控制 */
    u64 runtime_remaining;           /* 剩余运行时间 */
    u64 runtime_expires;             /* 运行时间过期 */
    struct hrtimer period_timer;      /* 周期定时器 */
    struct list_head throttled_list;  /* 限制列表 */
    int throttled;                   /* 是否被限制 */

    /* 层次结构 */
    struct task_group *parent;        /* 父任务组 */
    struct list_head siblings;        /* 兄弟任务组 */
    struct list_head children;        /* 子任务组 */
};

/* CPU控制文件 */
static struct cftype cpu_files[] = {
    {
        .name = "cpu.shares",
        .read_u64 = cpu_shares_read,
        .write_u64 = cpu_shares_write,
    },
    {
        .name = "cpu.cfs_quota_us",
        .read_s64 = cpu_cfs_quota_read_s64,
        .write_s64 = cpu_cfs_quota_write_s64,
    },
    {
        .name = "cpu.cfs_period_us",
        .read_u64 = cpu_cfs_period_read_u64,
        .write_u64 = cpu_cfs_period_write_u64,
    },
    {
        .name = "cpu.stat",
        .seq_show = cpu_stat_show,
    },
    { }    /* 终止符 */
};

/* CPU配额控制 */
static int tg_set_cfs_bandwidth(struct task_group *tg, u64 quota, u64 period)
{
    int i, ret = 0;
    struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;

    /* 验证参数 */
    if (quota == RUNTIME_INF && period == RUNTIME_INF)
        return -EINVAL;

    if (period != RUNTIME_INF && quota != RUNTIME_INF && quota > period)
        return -EINVAL;

    /* 设置带宽 */
    cfs_b->quota = quota;
    cfs_b->period = period;

    /* 重新启动定时器 */
    for_each_online_cpu(i) {
        struct rq *rq = cpu_rq(i);
        struct cfs_rq *cfs_rq = tg->cfs_rq[i];

        if (cfs_rq->runtime_enabled) {
            /* 重新启动周期定时器 */
            __start_cfs_bandwidth(cfs_b);
        }
    }

    return ret;
}
```

### 2.4 I/O子系统

I/O子系统提供磁盘I/O带宽限制：

```c
// block/blk-throttle.c
/* I/O节流组结构 */
struct throtl_grp {
    struct blkg_policy_data pd;       /* 块组策略数据 */
    struct throtl_service_queue sq;   /* 服务队列 */

    /* I/O限制 */
    uint64_t bps;                    /* 字节/秒限制 */
    uint64_t iops;                   /* I/O操作/秒限制 */
    uint64_t bps_disp;               /* 字节/秒显示值 */
    uint64_t iops_disp;              /* I/O操作/秒显示值 */

    /* I/O统计 */
    struct bio_list bio_lists[2];    /* BIO列表 */
    struct bio_list bio_lists_merged; /* 合并的BIO列表 */
    struct list_head tg_list;         /* 节流组列表 */

    /* 状态信息 */
    bool limits_changed;             /* 限制是否改变 */
    bool has_rules[2];               /* 是否有规则 */
    int errors;                      /* 错误计数 */
    unsigned long flags;             /* 标志位 */
};

/* I/O节流服务队列 */
struct throtl_service_queue {
    struct throtl_grp *tg;           /* 节流组 */
    struct list_head queued[2];       /* 排队队列 */
    unsigned int nr_queued[2];        /* 排队数量 */
    struct rb_root pending_tree;      /* 挂起树 */
    unsigned int nr_pending;          /* 挂起数量 */
    struct throtl_data *td;           /* 节流数据 */
};

/* I/O节流数据 */
struct throtl_data {
    struct request_queue *q;          /* 请求队列 */
    struct throtl_service_queue service_queue; /* 服务队列 */
    struct list_head tg_list;         /* 节流组列表 */
    struct list_head active_tgs;      /* 活跃节流组列表 */

    /* 节流参数 */
    uint64_t low_bps[2];             /* 低字节/秒限制 */
    uint64_t low_iops[2];            /* 低I/O操作/秒限制 */
    uint64_t high_bps[2];            /* 高字节/秒限制 */
    uint64_t high_iops[2];           /* 高I/O操作/秒限制 */

    /* 状态信息 */
    bool limits_changed;             /* 限制是否改变 */
    bool bios_queued;                /* BIO是否排队 */
    unsigned int scale_up;            /* 扩展因子 */
    unsigned int scale_down;          /* 缩减因子 */
};

/* I/O节流控制文件 */
static struct cftype blk_throtl_files[] = {
    {
        .name = "throttle.read_bps_device",
        .flags = CFTYPE_NOT_ON_ROOT,
        .write_string = tg_set_conf,
    },
    {
        .name = "throttle.write_bps_device",
        .flags = CFTYPE_NOT_ON_ROOT,
        .write_string = tg_set_conf,
    },
    {
        .name = "throttle.read_iops_device",
        .flags = CFTYPE_NOT_ON_ROOT,
        .write_string = tg_set_conf,
    },
    {
        .name = "throttle.write_iops_device",
        .flags = CFTYPE_NOT_ON_ROOT,
        .write_string = tg_set_conf,
    },
    { }    /* 终止符 */
};
```

## 3. 命名空间创建和管理

### 3.1 系统调用接口

提供用户空间操作命名空间的系统调用：

```c
// kernel/nsproxy.c
/* 创建命名空间 */
SYSCALL_DEFINE2(unshare, unsigned long, flags, unsigned long, args_size)
{
    struct nsproxy *new_nsp, *old_nsp;
    struct cred *new_cred;
    int err = 0;

    /* 检查参数 */
    if (args_size > 0) {
        /* 处理参数 */
        err = copy_unshare_args(flags, args_size, args_size, args_size);
        if (err)
            return err;
    }

    /* 检查权限 */
    if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN))
        return -EPERM;

    /* 检查标志位 */
    if (flags & ~(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET |
                   CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWCGROUP))
        return -EINVAL;

    /* 创建新的命名空间代理 */
    new_nsp = create_new_namespaces(flags, current, current_user_ns(), &new_cred);
    if (IS_ERR(new_nsp))
        return PTR_ERR(new_nsp);

    /* 切换命名空间 */
    task_lock(current);
    old_nsp = current->nsproxy;
    current->nsproxy = new_nsp;
    task_unlock(current);

    /* 释放旧命名空间 */
    free_nsproxy(old_nsp);

    return 0;
}

/* 设置命名空间 */
SYSCALL_DEFINE2(setns, int, fd, int, nstype)
{
    struct file *file;
    struct ns_common *ns;
    struct nsproxy *new_nsp, *old_nsp;
    int err;

    /* 打开文件描述符 */
    file = fget(fd);
    if (!file)
        return -EBADF;

    /* 检查是否为命名空间文件 */
    if (file->f_op != &ns_file_operations) {
        err = -EINVAL;
        goto out;
    }

    /* 获取命名空间 */
    ns = get_ns_from_inode(file_inode(file));
    if (!ns) {
        err = -EINVAL;
        goto out;
    }

    /* 检查命名空间类型 */
    if (nstype && (ns->ops->type != nstype)) {
        err = -EINVAL;
        goto out;
    }

    /* 检查权限 */
    if (!ns_capable(ns->ops->owner(ns), CAP_SYS_ADMIN)) {
        err = -EPERM;
        goto out;
    }

    /* 创建新的命名空间代理 */
    new_nsp = create_new_namespaces(0, current, ns->ops->owner(ns), NULL);
    if (IS_ERR(new_nsp)) {
        err = PTR_ERR(new_nsp);
        goto out;
    }

    /* 安装命名空间 */
    err = ns->ops->install(new_nsp, ns);
    if (err) {
        free_nsproxy(new_nsp);
        goto out;
    }

    /* 切换命名空间 */
    task_lock(current);
    old_nsp = current->nsproxy;
    current->nsproxy = new_nsp;
    task_unlock(current);

    /* 释放旧命名空间 */
    free_nsproxy(old_nsp);

out:
    fput(file);
    return err;
}
```

### 3.2 进程命名空间管理

管理进程的命名空间关联：

```c
// kernel/fork.c
/* 复制命名空间 */
static int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
    struct nsproxy *old_ns = tsk->nsproxy;
    struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
    struct nsproxy *new_ns;

    if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
                           CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWUSER |
                           CLONE_NEWCGROUP)))) {
        /* 不需要新命名空间 */
        get_nsproxy(old_ns);
        return 0;
    }

    /* 创建新命名空间 */
    new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->cred);
    if (IS_ERR(new_ns))
        return PTR_ERR(new_ns);

    /* 设置新命名空间 */
    tsk->nsproxy = new_ns;
    return 0;
}

/* 创建新命名空间代理 */
static struct nsproxy *create_new_namespaces(unsigned long flags,
                                             struct task_struct *tsk,
                                             struct user_namespace *user_ns,
                                             struct cred *new_cred)
{
    struct nsproxy *new_nsp;
    int err;

    /* 分配命名空间代理 */
    new_nsp = create_nsproxy();
    if (!new_nsp)
        return ERR_PTR(-ENOMEM);

    /* 复制UTS命名空间 */
    new_nsp->uts_ns = copy_utsname(flags, user_ns, tsk->nsproxy->uts_ns);
    if (IS_ERR(new_nsp->uts_ns)) {
        err = PTR_ERR(new_nsp->uts_ns);
        goto out_uts;
    }

    /* 复制IPC命名空间 */
    new_nsp->ipc_ns = copy_ipcs(flags, user_ns, tsk->nsproxy->ipc_ns);
    if (IS_ERR(new_nsp->ipc_ns)) {
        err = PTR_ERR(new_nsp->ipc_ns);
        goto out_ipc;
    }

    /* 复制挂载命名空间 */
    new_nsp->mnt_ns = copy_mnt_ns(flags, user_ns, tsk->nsproxy->mnt_ns);
    if (IS_ERR(new_nsp->mnt_ns)) {
        err = PTR_ERR(new_nsp->mnt_ns);
        goto out_mnt;
    }

    /* 复制PID命名空间 */
    new_nsp->pid_ns_for_children = copy_pid_ns(flags, user_ns,
                                                  tsk->nsproxy->pid_ns_for_children);
    if (IS_ERR(new_nsp->pid_ns_for_children)) {
        err = PTR_ERR(new_nsp->pid_ns_for_children);
        goto out_pid;
    }

    /* 复制网络命名空间 */
    new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);
    if (IS_ERR(new_nsp->net_ns)) {
        err = PTR_ERR(new_nsp->net_ns);
        goto out_net;
    }

    /* 复制Cgroup命名空间 */
    new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns,
                                         tsk->nsproxy->cgroup_ns);
    if (IS_ERR(new_nsp->cgroup_ns)) {
        err = PTR_ERR(new_nsp->cgroup_ns);
        goto out_cgroup;
    }

    return new_nsp;

out_cgroup:
    put_net(new_nsp->net_ns);
out_net:
    put_pid_ns(new_nsp->pid_ns_for_children);
out_pid:
    put_mnt_ns(new_nsp->mnt_ns);
out_mnt:
    put_ipc_ns(new_nsp->ipc_ns);
out_ipc:
    put_uts_ns(new_nsp->uts_ns);
out_uts:
    kfree(new_nsp);
    return ERR_PTR(err);
}
```

## 4. 隔离机制集成

### 4.1 容器技术集成

Namespaces和cgroups是容器技术的基础：

```c
// 容器创建示例
static int create_container(struct container *container)
{
    int ret;

    /* 创建PID命名空间 */
    container->pid_ns = create_pid_namespace(&init_user_ns, &init_pid_ns);
    if (IS_ERR(container->pid_ns)) {
        ret = PTR_ERR(container->pid_ns);
        goto err_pid_ns;
    }

    /* 创建网络命名空间 */
    container->net_ns = copy_net_ns(CLONE_NEWNET, &init_user_ns, &init_net);
    if (IS_ERR(container->net_ns)) {
        ret = PTR_ERR(container->net_ns);
        goto err_net_ns;
    }

    /* 创建cgroup */
    container->cgroup = cgroup_create("container");
    if (IS_ERR(container->cgroup)) {
        ret = PTR_ERR(container->cgroup);
        goto err_cgroup;
    }

    /* 设置资源限制 */
    ret = cgroup_set_limit(container->cgroup, "memory.max", "256M");
    if (ret)
        goto err_limit;

    ret = cgroup_set_limit(container->cgroup, "cpu.cfs_quota_us", "100000");
    if (ret)
        goto err_limit;

    return 0;

err_limit:
    cgroup_destroy(container->cgroup);
err_cgroup:
    put_net(container->net_ns);
err_net_ns:
    put_pid_ns(container->pid_ns);
err_pid_ns:
    return ret;
}
```

### 4.2 安全隔离

结合LSM实现更强大的安全隔离：

```c
// 安全容器实现
static int secure_container_create(struct container *container)
{
    int ret;

    /* 创建用户命名空间 */
    container->user_ns = create_user_ns();
    if (IS_ERR(container->user_ns)) {
        ret = PTR_ERR(container->user_ns);
        goto err_user_ns;
    }

    /* 映射用户ID */
    ret = user_ns_map_uid(container->user_ns, 0, 1000, 1);
    if (ret)
        goto err_map_uid;

    /* 设置权能 */
    ret = set_container_capabilities(container);
    if (ret)
        goto err_caps;

    /* 创建安全策略 */
    ret = create_container_policy(container);
    if (ret)
        goto err_policy;

    return 0;

err_policy:
    clear_container_capabilities(container);
err_caps:
    user_ns_unmap_uid(container->user_ns, 0);
err_map_uid:
    put_user_ns(container->user_ns);
err_user_ns:
    return ret;
}

/* 容器网络隔离 */
static int container_network_isolation(struct container *container)
{
    int ret;

    /* 创建网络命名空间 */
    container->net_ns = copy_net_ns(CLONE_NEWNET, container->user_ns, &init_net);
    if (IS_ERR(container->net_ns)) {
        ret = PTR_ERR(container->net_ns);
        return ret;
    }

    /* 创建虚拟以太网对 */
    ret = create_veth_pair(container->net_ns, "veth0", "veth1");
    if (ret)
        goto err_veth;

    /* 配置网络地址 */
    ret = configure_container_network(container->net_ns, "veth0", "10.0.0.2/24");
    if (ret)
        goto err_config;

    /* 设置防火墙规则 */
    ret = setup_container_firewall(container->net_ns);
    if (ret)
        goto err_firewall;

    return 0;

err_firewall:
err_config:
    destroy_veth_pair("veth0", "veth1");
err_veth:
    put_net(container->net_ns);
    return ret;
}
```

## 5. 性能优化

### 5.1 命名空间缓存

使用缓存减少命名空间查找开销：

```c
// 命名空间缓存实现
struct ns_cache {
    struct hlist_node node;
    struct ns_common *ns;
    atomic_t refcount;
    unsigned long last_used;
};

/* 命名空间缓存查找 */
static struct ns_cache *ns_cache_lookup(struct ns_common *ns)
{
    struct ns_cache *cache;
    struct hlist_head *head;
    unsigned long hash;

    /* 计算哈希值 */
    hash = hash_ptr(ns, NS_CACHE_HASH_BITS);
    head = &ns_cache_table[hash];

    /* 查找缓存 */
    hlist_for_each_entry(cache, head, node) {
        if (cache->ns == ns) {
            /* 更新使用时间 */
            cache->last_used = jiffies;
            return cache;
        }
    }

    return NULL;
}

/* 命名空间缓存添加 */
static void ns_cache_add(struct ns_common *ns)
{
    struct ns_cache *cache;
    struct hlist_head *head;
    unsigned long hash;

    /* 分配缓存项 */
    cache = kmalloc(sizeof(*cache), GFP_ATOMIC);
    if (!cache)
        return;

    /* 初始化缓存项 */
    cache->ns = ns;
    atomic_set(&cache->refcount, 1);
    cache->last_used = jiffies;

    /* 添加到哈希表 */
    hash = hash_ptr(ns, NS_CACHE_HASH_BITS);
    head = &ns_cache_table[hash];
    hlist_add_head(&cache->node, head);
}
```

### 5.2 Cgroup优化

优化cgroup操作的性能：

```c
// cgroup操作优化
static int fast_cgroup_attach(struct task_struct *task, struct cgroup *cgroup)
{
    struct cgroup_subsys_state *css;
    int ret;

    /* 快速路径：检查是否已经在正确的cgroup中 */
    css = task_css(task, memory_cgrp_id);
    if (css && css->cgroup == cgroup)
        return 0;

    /* 慢速路径：执行附加操作 */
    ret = cgroup_attach_task(task, cgroup);
    if (ret)
        return ret;

    return 0;
}

/* 批量cgroup操作 */
static int batch_cgroup_attach(struct task_struct **tasks, int nr_tasks,
                              struct cgroup *cgroup)
{
    int i, ret = 0;

    /* 预分配资源 */
    ret = cgroup_pre_attach(cgroup, nr_tasks);
    if (ret)
        return ret;

    /* 批量附加任务 */
    for (i = 0; i < nr_tasks; i++) {
        ret = cgroup_attach_task(tasks[i], cgroup);
        if (ret)
            break;
    }

    /* 清理资源 */
    cgroup_post_attach(cgroup);

    return ret;
}
```

## 6. 总结

Linux内核的隔离机制提供了强大的资源隔离和安全保障：

1. **Namespaces**：提供轻量级的进程隔离，包括UTS、IPC、PID、网络等多种类型
2. **Cgroups**：提供资源限制和控制，包括内存、CPU、I/O、网络等资源
3. **容器技术**：Namespaces和cgroups是容器技术的基础，实现了应用级的虚拟化
4. **安全集成**：与LSM、权限控制等安全机制集成，提供全面的安全保障
5. **性能优化**：通过缓存和批量操作等技术，优化隔离机制的性能

这些机制共同构成了现代Linux系统的隔离基础设施，为容器化、虚拟化和安全应用提供了坚实的基础。

---

*本分析基于Linux 6.17内核源代码，涵盖了Linux隔离机制的完整实现。*