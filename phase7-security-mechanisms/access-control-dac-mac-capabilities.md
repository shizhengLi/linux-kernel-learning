# Linux内核访问控制机制深度分析

## 概述
Linux内核实现了多层次的访问控制机制，包括传统的自主访问控制(DAC)、强制访问控制(MAC)和权能机制。这些机制共同构成了Linux系统的安全基础。本文基于Linux 6.17内核源代码，深入分析各种访问控制机制的实现原理和工作机制。

## 1. 自主访问控制 (DAC)

### 1.1 DAC架构概述

DAC基于传统的Unix权限模型，是Linux最基础的访问控制机制：

```c
// include/linux/fs.h
/* inode权限结构 */
struct inode {
    umode_t         i_mode;         /* 文件类型和权限 */
    uid_t           i_uid;          /* 用户ID */
    gid_t           i_gid;          /* 组ID */
    unsigned int    i_nlink;        /* 硬链接数 */
    dev_t           i_rdev;         /* 设备号 */
    loff_t          i_size;         /* 文件大小 */
    struct timespec64 i_atime;     /* 访问时间 */
    struct timespec64 i_mtime;     /* 修改时间 */
    struct timespec64 i_ctime;     /* 创建时间 */
    spinlock_t      i_lock;         /* 自旋锁 */
    /* ... */
};

/* 文件权限位定义 */
#define S_IRWXUGO        0777            /* RWX for user, group, other */
#define S_IRWXU          0700            /* RWX for owner */
#define S_IRUSR          0400            /* R for owner */
#define S_IWUSR          0200            /* W for owner */
#define S_IXUSR          0100            /* X for owner */
#define S_IRWXG          0070            /* RWX for group */
#define S_IRGRP          0040            /* R for group */
#define S_IWGRP          0020            /* W for group */
#define S_IXGRP          0010            /* X for group */
#define S_IRWXO          0007            /* RWX for other */
#define S_IROTH          0004            /* R for other */
#define S_IWOTH          0002            /* W for other */
#define S_IXOTH          0001            /* X for other */

/* 文件类型定义 */
#define S_IFMT           00170000        /* 文件类型掩码 */
#define S_IFSOCK         0140000         /* 套接字 */
#define S_IFLNK          0120000         /* 符号链接 */
#define S_IFREG          0100000         /* 普通文件 */
#define S_IFBLK          0060000         /* 块设备 */
#define S_IFDIR          0040000         /* 目录 */
#define S_IFCHR          0020000         /* 字符设备 */
#define S_IFIFO          0010000         /* 管道 */
```

### 1.2 权限检查机制

DAC的核心是权限检查函数：

```c
// fs/namei.c
/* 通用权限检查 */
int generic_permission(struct inode *inode, int mask)
{
    int ret = -EACCES;

    /* 检查文件是否可访问 */
    if (mask & MAY_NOT_BLOCK)
        return -ECHILD;

    /* 检查特权用户 */
    if (inode->i_uid == current_fsuid())
        ret = acl_permission_check(inode, mask & MAY_MASK, inode->i_mode >> 6);
    else if (in_group_p(inode->i_gid))
        ret = acl_permission_check(inode, mask & MAY_MASK, inode->i_mode >> 3);
    else
        ret = acl_permission_check(inode, mask & MAY_MASK, inode->i_mode);

    /* 检查附加权限 */
    if (ret == -EACCES && (mask & MAY_WRITE)) {
        /* 检查文件是否可写 */
        if (IS_IMMUTABLE(inode))
            return -EACCES;

        /* 检查文件系统是否只读 */
        if (IS_RDONLY(inode) && (mask & MAY_WRITE))
            return -EROFS;
    }

    return ret;
}

/* ACL权限检查 */
static int acl_permission_check(struct inode *inode, int mask, unsigned int mode)
{
    /* 检查读权限 */
    if (mask & (MAY_READ | MAY_EXEC | MAY_APPEND)) {
        if (!(mode & (S_IRUSR | S_IRGRP | S_IROTH)))
            return -EACCES;
    }

    /* 检查写权限 */
    if (mask & MAY_WRITE) {
        if (!(mode & (S_IWUSR | S_IWGRP | S_IWOTH)))
            return -EACCES;
    }

    /* 检查执行权限 */
    if (mask & MAY_EXEC) {
        if (!(mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
            return -EACCES;
    }

    return 0;
}

/* 快速路径权限检查 */
static inline int inode_permission_fast(struct inode *inode, int mask)
{
    /* 检查特权用户 */
    if (inode->i_uid == current_fsuid()) {
        /* 所有者权限 */
        if ((mask & MAY_READ) && !(inode->i_mode & S_IRUSR))
            return -EACCES;
        if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWUSR))
            return -EACCES;
        if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXUSR))
            return -EACCES;
    } else if (in_group_p(inode->i_gid)) {
        /* 组权限 */
        if ((mask & MAY_READ) && !(inode->i_mode & S_IRGRP))
            return -EACCES;
        if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWGRP))
            return -EACCES;
        if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXGRP))
            return -EACCES;
    } else {
        /* 其他用户权限 */
        if ((mask & MAY_READ) && !(inode->i_mode & S_IROTH))
            return -EACCES;
        if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWOTH))
            return -EACCES;
        if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXOTH))
            return -EACCES;
    }

    return 0;
}
```

### 1.3 特权用户检查

特权用户(root)可以绕过部分权限检查：

```c
// include/linux/cred.h
/* 凭据结构 */
struct cred {
    atomic_t usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t subscribers;    /* 订阅者数量 */
#endif
    uid_t uid;              /* 真实用户ID */
    gid_t gid;              /* 真实组ID */
    uid_t suid;             /* 保存的用户ID */
    gid_t sgid;             /* 保存的组ID */
    uid_t euid;             /* 有效用户ID */
    gid_t egid;             /* 有效组ID */
    uid_t fsuid;            /* 文件系统用户ID */
    gid_t fsgid;            /* 文件系统组ID */
    unsigned securebits;     /* 安全位 */
    kernel_cap_t cap_inheritable; /* 可继承的权能 */
    kernel_cap_t cap_permitted;    /* 允许的权能 */
    kernel_cap_t cap_effective;    /* 有效的权能 */
    kernel_cap_t cap_bset;         /* 权能边界集 */
    kernel_cap_t cap_ambient;       /* 环境权能 */
    struct user_struct *user;       /* 用户结构 */
    struct user_namespace *user_ns; /* 用户命名空间 */
    struct group_info *group_info;  /* 组信息 */
    struct rcu_head rcu;             /* RCU头部 */
};

/* 特权检查函数 */
static inline int capable(int cap)
{
    return ns_capable(&init_user_ns, cap);
}

/* 命名空间权能检查 */
bool ns_capable(struct user_namespace *ns, int cap)
{
    if (WARN_ON_ONCE(!ns))
        return false;

    return security_capable(current_cred(), ns, cap, CAP_OPT_NONE) == 0;
}

/* 文件系统特权检查 */
static inline int capable_wrt_inode_uidgid(const struct inode *inode, int cap)
{
    struct user_namespace *ns = current_user_ns();

    /* 检查用户是否拥有特权 */
    if (ns_capable(ns, cap))
        return 1;

    /* 检查文件所有者 */
    if (inode->i_uid == current_fsuid())
        return 1;

    /* 检查特权用户 */
    if (ns_capable(inode->i_sb->s_user_ns, cap))
        return 1;

    return 0;
}
```

## 2. 强制访问控制 (MAC)

### 2.1 MAC架构设计

MAC提供比DAC更细粒度的访问控制，不受用户自主决策的影响：

```c
// security/selinux/include/security.h
/* SELinux安全上下文 */
struct selinux_ctx {
    u32 user;      /* 用户标识 */
    u32 role;      /* 角色标识 */
    u32 type;      /* 类型标识 */
    u32 len;       /* 上下文长度 */
    char *str;     /* 上下文字符串 */
};

/* 安全上下文缓存 */
struct selinux_avc {
    struct avc_cache *cache;
    spinlock_t lock;
    struct selinux_ctx *current_ctx;
    struct selinux_ctx *target_ctx;
};

/* 访问向量缓存 */
struct avc_cache {
    struct hlist_head slots[AVC_CACHE_SLOTS];
    spinlock_t slots_lock[AVC_CACHE_SLOTS];
    atomic_t lru_hint;
    atomic_t active_nodes;
    u32 latest_notif;
};
```

### 2.2 SELinux MAC实现

SELinux是最著名的MAC实现：

```c
// security/selinux/hooks.c
/* SELinux权限检查 */
static int selinux_inode_permission(struct inode *inode, int mask)
{
    const struct cred *cred = current_cred();
    struct selinux_audit_data ad;
    u32 sid = cred_sid(cred);          /* 主体安全标识 */
    u32 isec_sid = inode_security_sid(inode); /* 客体安全标识 */
    int rc;

    /* 初始化审计数据 */
    ad.type = LSM_AUDIT_DATA_INODE;
    ad.u.inode = inode;

    /* 检查读权限 */
    if (mask & (MAY_READ | MAY_EXEC | MAY_APPEND)) {
        rc = avc_has_perm(sid, isec_sid, SECCLASS_FILE, FILE__READ, &ad);
        if (rc)
            return rc;
    }

    /* 检查写权限 */
    if (mask & MAY_WRITE) {
        rc = avc_has_perm(sid, isec_sid, SECCLASS_FILE, FILE__WRITE, &ad);
        if (rc)
            return rc;
    }

    /* 检查执行权限 */
    if (mask & MAY_EXEC) {
        rc = avc_has_perm(sid, isec_sid, SECCLASS_FILE, FILE__EXECUTE, &ad);
        if (rc)
            return rc;
    }

    /* 检查搜索权限 */
    if (mask & MAY_SEARCH) {
        rc = avc_has_perm(sid, isec_sid, SECCLASS_DIR, DIR__SEARCH, &ad);
        if (rc)
            return rc;
    }

    return 0;
}

/* 访问向量检查 */
int avc_has_perm(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                 struct selinux_audit_data *ad)
{
    struct av_decision avd;
    u32 denied;
    int rc;

    /* 检查访问向量缓存 */
    rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, 0, &avd);
    if (rc == 0) {
        /* 访问允许 */
        return 0;
    }

    /* 计算被拒绝的权限 */
    denied = requested & ~(avd.allowed);

    /* 记录审计日志 */
    if (!(avd.flags & AVD_FLAGS_PERMISSIVE)) {
        avc_audit(ssid, tsid, tclass, requested, denied, &ad);
    }

    /* 根据模式决定返回值 */
    if (avd.flags & AVD_FLAGS_PERMISSIVE) {
        /* 宽松模式：记录但不拒绝 */
        return 0;
    } else {
        /* 强制模式：拒绝访问 */
        return -EACCES;
    }
}
```

### 2.3 类型强制 (Type Enforcement)

SELinux的核心是类型强制机制：

```c
// security/selinux/ss/ebitmap.h
/* 扩展位图 */
struct ebitmap {
    struct ebitmap_node *node;
    unsigned long highbit;
};

/* 扩展位图节点 */
struct ebitmap_node {
    struct hlist_node list;
    unsigned long startmap;
    unsigned long map[0];
};

/* 安全上下文 */
struct context {
    u32 user;
    u32 role;
    u32 type;
    u32 len;
    char *str;
};

/* 策略数据库 */
struct policydb {
    struct symtab symtab[SYM_NUM];
    struct ocontext *ocontexts[OCON_NUM];
    struct genfs *genfs;
    struct hashtab *p_types_table;
    struct hashtab *p_roles_table;
    struct hashtab *p_users_table;
    struct hashtab *p_bools_table;
    struct ebitmap policycaps;
    struct ebitmap permissive_map;
};

/* 类型检查 */
static int type_has_perm(u32 sid, u32 tsid, u16 tclass, u32 requested)
{
    struct context *scontext, *tcontext;
    struct avtab_key avkey;
    struct avtab_datum *avdatum;
    struct av_decision avd;
    u32 allowed = 0;
    int rc;

    /* 获取主体和客体的安全上下文 */
    scontext = sid2context(sid);
    tcontext = sid2context(tsid);

    /* 设置访问向量键 */
    avkey.source_type = scontext->type;
    avkey.target_type = tcontext->type;
    avkey.target_class = tclass;

    /* 查找访问向量 */
    avdatum = avtab_search(&policydb.te_avtab, &avkey);
    if (avdatum) {
        allowed = avdatum->allowed;
    }

    /* 检查权限 */
    if ((requested & allowed) == requested) {
        return 0;
    }

    return -EACCES;
}
```

## 3. 权能机制 (Capabilities)

### 3.1 权能系统架构

Capabilities将root权限分解为细粒度的权限单元：

```c
// include/linux/capability.h
/* 权能定义 */
#define CAP_CHOWN            0    /* 修改文件所有者 */
#define CAP_DAC_OVERRIDE     1    /* 绕过文件权限检查 */
#define CAP_DAC_READ_SEARCH  2    /* 绕过读权限和搜索权限 */
#define CAP_FOWNER           3    /* 绕过文件所有者检查 */
#define CAP_FSETID           4    /* 设置文件setuid/setgid位 */
#define CAP_KILL             5    /* 绕过进程信号权限检查 */
#define CAP_SETGID           6    /* 设置进程组ID */
#define CAP_SETUID           7    /* 设置进程用户ID */
#define CAP_SETPCAP          8    /* 修改权能边界集 */
#define CAP_LINUX_IMMUTABLE  9    /* 修改不可变文件属性 */
#define CAP_NET_BIND_SERVICE 10   /* 绑定特权端口 */
#define CAP_NET_BROADCAST    11   /* 发送广播包 */
#define CAP_NET_ADMIN        12   /* 网络管理 */
#define CAP_NET_RAW          13   /* 原始套接字 */
#define CAP_IPC_LOCK         14   /* 锁定共享内存 */
#define CAP_IPC_OWNER        15   /* 绕过IPC权限检查 */
#define CAP_SYS_MODULE       16   /* 加载/卸载内核模块 */
#define CAP_SYS_RAWIO        17   /* 原始I/O访问 */
#define CAP_SYS_CHROOT       18   /* 使用chroot */
#define CAP_SYS_PTRACE       19   /* 调试任意进程 */
#define CAP_SYS_PACCT        20   /* 进程记账 */
#define CAP_SYS_ADMIN        21   /* 系统管理 */
#define CAP_SYS_BOOT         22   /* 重启系统 */
#define CAP_SYS_NICE         23   /* 修改进程优先级 */
#define CAP_SYS_RESOURCE     24   /* 资源限制 */
#define CAP_SYS_TIME         25   /* 修改系统时间 */
#define CAP_SYS_TTY_CONFIG   26   /* 配置TTY */
#define CAP_MKNOD            27   /* 创建设备文件 */
#define CAP_LEASE            28   /* 建立文件租约 */
#define CAP_AUDIT_WRITE      29   /* 写入审计日志 */
#define CAP_AUDIT_CONTROL    30   /* 控制审计系统 */
#define CAP_SETFCAP          31   /* 设置文件权能 */
#define CAP_MAC_OVERRIDE     32   /* 绕过MAC强制访问控制 */
#define CAP_MAC_ADMIN        33   /* MAC管理 */
#define CAP_SYSLOG           34   /* 内核日志 */
#define CAP_WAKE_ALARM       35   /* 唤醒系统 */
#define CAP_BLOCK_SUSPEND    36   /* 阻止系统挂起 */
#define CAP_AUDIT_READ       37   /* 读取审计日志 */
#define CAP_PERFMON          38   /* 性能监控 */
#define CAP_BPF              39   /* BPF管理 */
#define CAP_CHECKPOINT_RESTORE 40  /* 检查点恢复 */

/* 权能集结构 */
typedef struct kernel_cap_struct {
    __u32 cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

/* 权能检查宏 */
#define CAP_FOR_EACH_U32(__capi) \
    for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)

#define CAP_FSSET_BOP(c, flag)    (c.cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define CAP_FSET_BOP(c, flag)     (c.cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define CAP_FSRAISE_BOP(c, flag)  (c.cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define CAP_FRAISE_BOP(c, flag)   (c.cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define CAP_FSWITCH_BOP(c, flag)  (c.cap[CAP_TO_INDEX(flag)] ^= CAP_TO_MASK(flag))
```

### 3.2 权能检查实现

权能检查的核心函数：

```c
// kernel/capability.c
/* 权能检查 */
bool has_capability(struct task_struct *t, int cap)
{
    struct user_namespace *ns = current_user_ns();
    int ret;

    rcu_read_lock();
    ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NONE);
    rcu_read_unlock();

    return ret == 0;
}

/* 命名空间权能检查 */
bool ns_capable(struct user_namespace *ns, int cap)
{
    if (WARN_ON_ONCE(!ns))
        return false;

    return security_capable(current_cred(), ns, cap, CAP_OPT_NONE) == 0;
}

/* 权能提升检查 */
bool capable(int cap)
{
    return ns_capable(&init_user_ns, cap);
}

/* 文件系统权能检查 */
bool capable_wrt_inode_uidgid(const struct inode *inode, int cap)
{
    struct user_namespace *ns = current_user_ns();

    if (ns_capable(ns, cap))
        return true;

    if (inode->i_uid == current_fsuid())
        return true;

    if (ns_capable(inode->i_sb->s_user_ns, cap))
        return true;

    return false;
}

/* 有效权能检查 */
bool file_ns_capable(const struct file *file, struct user_namespace *ns, int cap)
{
    if (file->f_cred->user_ns == ns) {
        /* 文件创建者的命名空间 */
        if (ns_capable(ns, cap))
            return true;
    }

    /* 当前进程的命名空间 */
    if (ns_capable(current_user_ns(), cap))
        return true;

    return false;
}
```

### 3.3 权能继承和管理

权能的继承和管理机制：

```c
// kernel/capability.c
/* 权能继承规则 */
static inline void cap_inherit(const struct cred *old, struct cred *new)
{
    /* 继承可继承的权能 */
    new->cap_inheritable = old->cap_inheritable;

    /* 继承允许的权能 */
    new->cap_permitted = old->cap_permitted;

    /* 重置有效权能 */
    cap_clear(new->cap_effective);

    /* 重置环境权能 */
    cap_clear(new->cap_ambient);
}

/* 设置有效权能 */
int cap_set_effective(const kernel_cap_t *effective)
{
    struct cred *new;
    int ret;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* 设置有效权能 */
    new->cap_effective = *effective;

    /* 确保有效权能不超过允许权能 */
    if (!cap_issubset(*effective, new->cap_permitted)) {
        abort_creds(new);
        return -EPERM;
    }

    /* 应用新的凭据 */
    return commit_creds(new);
}

/* 设置权能边界集 */
int cap_set_bound(kernel_cap_t *new_caps)
{
    struct cred *new;
    int ret;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* 检查是否移除已有的权能 */
    if (!cap_issubset(*new_caps, new->cap_bset)) {
        abort_creds(new);
        return -EPERM;
    }

    /* 设置新的边界集 */
    new->cap_bset = *new_caps;

    return commit_creds(new);
}

/* 设置环境权能 */
int cap_set_ambient(kernel_cap_t *ambient)
{
    struct cred *new;
    int ret;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* 确保环境权能不超过可继承权能 */
    if (!cap_issubset(*ambient, new->cap_inheritable)) {
        abort_creds(new);
        return -EPERM;
    }

    /* 设置环境权能 */
    new->cap_ambient = *ambient;

    return commit_creds(new);
}
```

## 4. 访问控制集成

### 4.1 综合权限检查

Linux内核将多种访问控制机制集成在一起：

```c
// fs/namei.c
/* 文件打开权限检查 */
int may_open(struct path *path, int acc_mode, int flag)
{
    struct dentry *dentry = path->dentry;
    struct inode *inode = dentry->d_inode;
    int error = 0;

    /* DAC权限检查 */
    error = inode_permission(inode, acc_mode);
    if (error)
        return error;

    /* 检查文件类型 */
    if (S_ISDIR(inode->i_mode)) {
        if (acc_mode & MAY_WRITE) {
            return -EISDIR;
        }
    }

    /* 检查特殊文件 */
    if (S_ISLNK(inode->i_mode)) {
        if (acc_mode & MAY_WRITE) {
            return -ELOOP;
        }
    }

    /* 检查只读文件系统 */
    if (IS_RDONLY(inode) && (acc_mode & MAY_WRITE)) {
        return -EROFS;
    }

    /* 检查不可变文件 */
    if (IS_IMMUTABLE(inode) && (acc_mode & MAY_WRITE)) {
        return -EACCES;
    }

    /* 调用LSM模块检查 */
    error = security_file_open(file, const cred *cred);
    if (error)
        return error;

    return 0;
}

/* 进程执行权限检查 */
static int check_exec_permission(struct inode *inode)
{
    int error = 0;

    /* DAC权限检查 */
    error = inode_permission(inode, MAY_EXEC);
    if (error)
        return error;

    /* 检查文件类型 */
    if (!S_ISREG(inode->i_mode))
        return -EACCES;

    /* 检查文件是否可执行 */
    if (inode->i_mode & 0111)
        return -EACCES;

    /* 调用LSM模块检查 */
    error = security_file_permission(file, MAY_EXEC);
    if (error)
        return error;

    return 0;
}
```

### 4.2 网络访问控制

网络访问控制集成多种机制：

```c
// net/core/security.c
/* 网络数据包接收检查 */
int netif_rx(struct sk_buff *skb)
{
    int ret;

    /* 网络协议栈处理 */
    ret = netif_rx_internal(skb);
    if (ret != NET_RX_DROP)
        return ret;

    /* 调用LSM模块检查 */
    if (security_sock_rcv_skb(skb->sk, skb) != 0) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    return ret;
}

/* 套接字绑定检查 */
int sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    int error;

    /* 基本参数检查 */
    error = sock->ops->bind(sock, addr, addr_len);
    if (error)
        return error;

    /* 权能检查 */
    if (sock->type == SOCK_RAW) {
        /* 原始套接字需要NET_RAW权能 */
        if (!capable(CAP_NET_RAW))
            return -EPERM;
    }

    /* 特权端口检查 */
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        if (sin->sin_port < htons(1024)) {
            /* 绑定特权端口需要NET_BIND_SERVICE权能 */
            if (!capable(CAP_NET_BIND_SERVICE))
                return -EACCES;
        }
    }

    /* 调用LSM模块检查 */
    error = security_socket_bind(sock, addr, addr_len);
    if (error)
        return error;

    return 0;
}
```

## 5. 性能优化

### 5.1 快速路径优化

访问控制的性能优化：

```c
// fs/namei.c
/* 快速权限检查 */
static inline int fast_path_permission(struct inode *inode, int mask)
{
    /* 特权用户快速通过 */
    if (inode->i_uid == current_fsuid()) {
        if ((mask & MAY_READ) && !(inode->i_mode & S_IRUSR))
            return -EACCES;
        if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWUSR))
            return -EACCES;
        if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXUSR))
            return -EACCES;
        return 0;
    }

    /* 组权限快速检查 */
    if (in_group_p(inode->i_gid)) {
        if ((mask & MAY_READ) && !(inode->i_mode & S_IRGRP))
            return -EACCES;
        if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWGRP))
            return -EACCES;
        if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXGRP))
            return -EACCES;
        return 0;
    }

    /* 其他用户权限检查 */
    if ((mask & MAY_READ) && !(inode->i_mode & S_IROTH))
        return -EACCES;
    if ((mask & MAY_WRITE) && !(inode->i_mode & S_IWOTH))
        return -EACCES;
    if ((mask & MAY_EXEC) && !(inode->i_mode & S_IXOTH))
        return -EACCES;

    return 0;
}

/* 权能检查优化 */
static inline bool fast_capable(int cap)
{
    /* 检查有效权能 */
    if (cap_raised(current_cred()->cap_effective, cap))
        return true;

    /* 检查特权用户 */
    if (current_cred()->uid == 0)
        return true;

    return false;
}
```

### 5.2 缓存机制

使用缓存减少重复计算：

```c
// security/selinux/avc.c
/* 访问向量缓存 */
struct avc_node {
    struct hlist_node list;
    struct rcu_head rhead;
    struct avc_entry *ae;
    struct avc_cache *cache;
    u32 avd.seqno;
};

/* 缓存查找 */
static struct avc_node *avc_lookup(struct avc_cache *cache, u32 ssid, u32 tsid,
                                   u16 tclass, u32 requested)
{
    struct avc_node *node;
    struct hlist_head *head;
    unsigned int hash;

    /* 计算哈希值 */
    hash = avc_hash(ssid, tsid, tclass, requested);
    head = &cache->slots[hash];

    /* 查找缓存项 */
    hlist_for_each_entry_rcu(node, head, list) {
        if (node->ae->ssid == ssid && node->ae->tsid == tsid &&
            node->ae->tclass == tclass && node->ae->requested == requested) {
            /* 缓存命中 */
            return node;
        }
    }

    return NULL;
}

/* 缓存更新 */
static void avc_update_node(struct avc_node *node, u32 ssid, u32 tsid,
                           u16 tclass, u32 requested, struct av_decision *avd)
{
    /* 更新缓存项 */
    node->ae->ssid = ssid;
    node->ae->tsid = tsid;
    node->ae->tclass = tclass;
    node->ae->requested = requested;
    node->ae->avd.allowed = avd->allowed;
    node->ae->avd.decided = avd->decided;
    node->ae->avd.auditallow = avd->auditallow;
    node->ae->avd.auditdeny = avd->auditdeny;
    node->ae->avd.seqno = avd->seqno;
}
```

## 6. 实际应用示例

### 6.1 容器安全策略

容器环境中的访问控制：

```c
// 容器权能限制
static int container_drop_capabilities(void)
{
    struct cred *new;
    kernel_cap_t caps = CAP_EMPTY_SET;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* 只保留必要的权能 */
    cap_raise(caps, CAP_NET_BIND_SERVICE);
    cap_raise(caps, CAP_SETGID);
    cap_raise(caps, CAP_SETUID);
    cap_raise(caps, CAP_SETPCAP);

    /* 设置权能 */
    new->cap_permitted = caps;
    new->cap_effective = caps;
    new->cap_bset = caps;

    return commit_creds(new);
}

/* 容器文件系统隔离 */
static int container_file_permission(struct inode *inode, int mask)
{
    struct task_struct *task = current;
    struct pid_namespace *pid_ns = task_active_pid_ns(task);

    /* 检查是否在容器中 */
    if (pid_ns != &init_pid_ns) {
        /* 容器内额外的权限检查 */
        if (mask & MAY_WRITE) {
            /* 检查文件是否在容器根目录外 */
            if (!is_within_container_root(inode, task)) {
                return -EACCES;
            }
        }
    }

    return 0;
}
```

### 6.2 最小权限原则

实现最小权限原则的示例：

```c
// 最小权限进程配置
static int setup_minimal_privileges(void)
{
    struct cred *new;
    kernel_cap_t minimal_caps = CAP_EMPTY_SET;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* 只保留必要的权能 */
    cap_raise(minimal_caps, CAP_SETUID);
    cap_raise(minimal_caps, CAP_SETGID);
    cap_raise(minimal_caps, CAP_DAC_READ_SEARCH);

    /* 设置权能 */
    new->cap_permitted = minimal_caps;
    new->cap_effective = minimal_caps;
    new->cap_bset = minimal_caps;

    /* 清除环境权能 */
    cap_clear(new->cap_ambient);

    return commit_creds(new);
}

/* 安全文件访问 */
static int secure_file_access(const char *filename, int flags)
{
    struct file *file;
    int ret;

    /* 打开文件 */
    file = filp_open(filename, flags, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);

    /* 检查文件权限 */
    if (flags & O_WRONLY) {
        /* 写操作需要额外检查 */
        if (!capable(CAP_DAC_OVERRIDE)) {
            filp_close(file, NULL);
            return -EACCES;
        }
    }

    filp_close(file, NULL);
    return 0;
}
```

## 7. 总结

Linux内核访问控制机制提供了一个多层次的安全框架：

1. **DAC (自主访问控制)**：传统的Unix权限模型，简单直观
2. **MAC (强制访问控制)**：细粒度的访问控制，不受用户决策影响
3. **Capabilities (权能)**：细粒度的特权分离，避免全权root用户
4. **集成机制**：多种访问控制机制协同工作
5. **性能优化**：快速路径和缓存机制减少开销

这些机制共同构成了Linux系统的安全基础，为不同级别的安全需求提供了灵活的解决方案。理解这些机制对于系统安全配置、安全策略制定和安全软件开发都具有重要意义。

---

*本分析基于Linux 6.17内核源代码，涵盖了Linux访问控制机制的完整实现。*