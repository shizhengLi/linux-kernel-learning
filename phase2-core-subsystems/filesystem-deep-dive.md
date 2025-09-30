# Linux内核文件系统子系统深度解析

## 1. 文件系统概述

Linux文件系统子系统采用分层架构设计，通过虚拟文件系统(VFS)提供统一的文件操作接口，支持多种具体文件系统的实现。这种设计使得用户可以使用相同的方式访问不同类型的文件系统。

### 1.1 VFS抽象层架构

```c
/* VFS核心数据结构关系 */
/*
 * 用户应用程序
 *     ↓ (系统调用)
 * 系统调用接口 (sys_read, sys_write, sys_open等)
 *     ↓
 * 虚拟文件系统(VFS)
 *     ↓
 * 具体文件系统 (ext4, xfs, procfs等)
 *     ↓
 * 块设备层 / 缓存层
 *     ↓
 * 设备驱动
 */

/* VFS核心对象 */
struct super_block;    /* 超级块 - 文件系统全局信息 */
struct inode;          /* 索引节点 - 文件元数据 */
struct dentry;         /* 目录项 - 路径名缓存 */
struct file;           /* 文件 - 进程打开的文件 */
struct vfsmount;       /* 挂载点 - 文件系统挂载信息 */
```

### 1.2 文件系统注册机制

```c
/* 文件系统类型 */
struct file_system_type {
    const char *name;           /* 文件系统名称 */
    int fs_flags;              /* 文件系统标志 */
    int (*init_fs_context)(struct fs_context *); /* 初始化文件系统上下文 */
    const struct fs_parameter_spec *parameters; /* 参数规范 */
    int (*kill_sb)(struct super_block *);      /* 销毁超级块 */

    struct module *owner;      /* 拥有者模块 */
    struct file_system_type *next;  /* 下一个文件系统类型 */
    struct hlist_head fs_supers; /* 超级块哈希表 */

    struct lock_class_key s_lock_key;
    struct lock_class_key s_um_key;
    struct lock_class_key i_lock_key;
    struct lock_class_key i_mutex_key;
};

/* 文件系统注册 */
int register_filesystem(struct file_system_type *fs)
{
    int res = 0;
    struct file_system_type **p;

    /* 检查是否已注册 */
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strcmp((*p)->name, fs->name) == 0) {
            res = -EBUSY;
            goto out;
        }

    /* 添加到链表 */
    fs->next = *p;
    *p = fs;
    write_unlock(&file_systems_lock);

out:
    return res;
}

/* 文件系统注销 */
void unregister_filesystem(struct file_system_type *fs)
{
    struct file_system_type **tmp;

    write_lock(&file_systems_lock);
    for (tmp = &file_systems; *tmp; tmp = &(*tmp)->next) {
        if (*tmp == fs) {
            *tmp = fs->next;
            fs->next = NULL;
            break;
        }
    }
    write_unlock(&file_systems_lock);
}
```

## 2. 超级块管理

### 2.1 超级块结构

```c
/* 超级块 - 文件系统全局信息 */
struct super_block {
    struct list_head s_list;    /* 所有超级块的链表 */
    dev_t s_dev;                /* 设备标识符 */
    unsigned char s_blocksize_bits; /* 块大小位数 */
    unsigned long s_blocksize;  /* 块大小 */
    loff_t s_maxbytes;          /* 最大文件大小 */
    struct file_system_type *s_type; /* 文件系统类型 */
    const struct super_operations *s_op; /* 超级块操作 */
    const struct dquot_operations *dq_op; /* 磁盘配额操作 */
    const struct quotactl_ops *s_qcop;    /* 配额控制操作 */
    const struct export_operations *s_export_op; /* 导出操作 */

    unsigned long s_flags;       /* 挂载标志 */
    unsigned long s_magic;       /* 文件系统魔数 */
    struct dentry *s_root;      /* 根目录项 */
    struct rw_semaphore s_umount; /* 卸载信号量 */
    struct mutex s_lock;        /* 超级块互斥锁 */

    int s_count;                /* 引用计数 */
    atomic_t s_active;          /* 活跃引用计数 */
    void *s_fs_info;            /* 文件系统私有数据 */

    /* 统计信息 */
    struct percpu_counter s_files; /* 文件计数 */
    struct percpu_counter s_mounts; /* 挂载计数 */
    struct percpu_counter s_dentrys; /* 目录项计数 */
    struct percpu_counter s_inodes;  /* 索引节点计数 */

    /* 时间信息 */
    time64_t s_time_gran;       /* 时间粒度 */
    time64_t s_time_min;        /* 最小时间 */
    time64_t s_time_max;        /* 最大时间 */

    /* 等待队列 */
    wait_queue_head_t s_wait_unfrozen; /* 解冻等待队列 */

    /* 块设备信息 */
    struct block_device *s_bdev; /* 块设备 */
    struct backing_dev_info *s_bdi; /* 回设备信息 */

    /* 垃圾回收 */
    struct list_lru s_dentry_lru; /* 目录项LRU */
    struct list_lru s_inode_lru;  /* 索引节点LRU */

    /* 安全信息 */
    void *s_security;           /* 安全模块数据 */

    /* X信息 */
    struct list_head s_inodes;   /* 所有索引节点 */
    struct list_head s_dentries; /* 所有目录项 */

    /* ... 更多字段 */
};
```

### 2.2 超级块操作

```c
/* 超级块操作 */
struct super_operations {
    /* 分配索引节点 */
    struct inode *(*alloc_inode)(struct super_block *sb);

    /* 销毁索引节点 */
    void (*destroy_inode)(struct inode *);

    /* 写入索引节点 */
    int (*write_inode)(struct inode *, struct writeback_control *wbc);

    /* 删除索引节点 */
    void (*evict_inode)(struct inode *);

    /* 放置超级块 */
    void (*put_super)(struct super_block *);

    /* 同步文件系统 */
    int (*sync_fs)(struct super_block *sb, int wait);

    /* 冻结文件系统 */
    int (*freeze_fs)(struct super_block *);

    /* 解冻文件系统 */
    int (*unfreeze_fs)(struct super_block *);

    /* 统计信息 */
    int (*statfs)(struct dentry *, struct kstatfs *);

    /* 重新挂载 */
    int (*remount_fs)(struct super_block *, int *, char *);

    /* 卸载文件系统 */
    void (*umount_begin)(struct super_block *);

    /* 截断文件 */
    int (*drop_inode)(struct inode *);

    /* 标记脏块 */
    void (*dirty_inode) (struct inode *, int flags);

    /* 写入超级块 */
    int (*write_super) (struct super_block *);

    /* 写回索引节点 */
    int (*writepages)(struct address_space *, struct writeback_control *);

    /* 读取索引节点 */
    int (*read_inode)(struct inode *);

    /* 写回索引节点 */
    int (*write_inode)(struct inode *, struct writeback_control *);

    /* 属性处理 */
    int (*setattr)(struct dentry *, struct iattr *);
    int (*getattr)(struct vfsmount *mnt, struct dentry *, struct kstat *);
    int (*permission)(struct inode *, int);

    /* 目录项操作 */
    int (*setxattr)(struct dentry *, const char *, const void *, size_t, int);
    ssize_t (*getxattr)(struct dentry *, const char *, void *, size_t);
    ssize_t (*listxattr)(struct dentry *, char *, size_t);
    int (*removexattr)(struct dentry *, const char *);

    /* 文件系统信息 */
    void (*destroy_inode)(struct inode *);
    int (*statfs)(struct dentry *, struct kstatfs *);
    int (*remount_fs)(struct super_block *, int *, char *);
    void (*clear_inode)(struct inode *);
    int (*show_options)(struct seq_file *, struct dentry *);
    ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
    ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
};

/* 读取超级块 */
struct super_block *sget(struct file_system_type *type,
              int (*test)(struct super_block *,void *),
              int (*set)(struct super_block *,void *),
              int flags, void *data)
{
    struct super_block *s = NULL;
    struct super_block *old;
    int err;

    /* 搜索现有超级块 */
retry:
    list_for_each_entry(old, &type->fs_supers, s_instances) {
        if (!test(old, data))
            continue;

        /* 检查是否可以共享 */
        if (!grab_super(old))
            goto retry;

        if (s) {
            up_write(&s->s_umount);
            destroy_super(s);
            s = NULL;
        }
        return old;
    }

    /* 分配新超级块 */
    if (!s) {
        s = alloc_super(type, flags);
        if (!s)
            return ERR_PTR(-ENOMEM);
    }

    /* 初始化超级块 */
    err = set(s, data);
    if (err) {
        up_write(&s->s_umount);
        destroy_super(s);
        return ERR_PTR(err);
    }

    /* 添加到文件系统类型 */
    s->s_type = type;
    strlcpy(s->s_id, type->name, sizeof(s->s_id));
    list_add_tail(&s->s_instances, &type->fs_supers);

    return s;
}
```

## 3. 索引节点管理

### 3.1 inode结构

```c
/* 索引节点 - 文件元数据 */
struct inode {
    umode_t i_mode;             /* 文件类型和权限 */
    unsigned short i_opflags;   /* 操作标志 */
    kuid_t i_uid;               /* 用户ID */
    kgid_t i_gid;               /* 组ID */
    unsigned int i_flags;       /* 文件标志 */
    dev_t i_rdev;               /* 设备号 */

    /* 时间戳 */
    struct timespec64 i_atime;  /* 访问时间 */
    struct timespec64 i_mtime;  /* 修改时间 */
    struct timespec64 i_ctime;  /* 创建时间 */
    struct timespec64 i_btime;  /* 出生时间 */

    /* 文件大小 */
    loff_t i_size;              /* 文件大小 */
    loff_t i_bytes;             /* 实际字节数 */
    blkcnt_t i_blocks;          /* 占用块数 */

    /* 索引节点号 */
    unsigned long i_ino;        /* 索引节点号 */
    unsigned int i_nlink;       /* 硬链接数 */

    /* 引用计数 */
    atomic_t i_count;           /* 引用计数 */
    atomic_t i_writecount;      /* 写入者计数 */
    atomic_t i_readcount;       /* 读取者计数 */

    /* 操作函数 */
    const struct inode_operations *i_op; /* 索引节点操作 */
    const struct file_operations *i_fop; /* 文件操作 */
    struct super_block *i_sb;   /* 所属超级块 */

    /* 地址空间 */
    struct address_space *i_mapping; /* 地址空间 */
    struct address_space i_data; /* 默认地址空间 */

    /* 文件系统私有数据 */
    void *i_private;            /* 私有数据 */

    /* 链表管理 */
    struct list_head i_devices; /* 设备链表 */
    union {
        struct pipe_inode_info *i_pipe;   /* 管道信息 */
        struct block_device *i_bdev;      /* 块设备 */
        struct cdev *i_cdev;              /* 字符设备 */
    };

    /* 锁机制 */
    spinlock_t i_lock;          /* 索引节点锁 */
    struct mutex i_mutex;       /* 互斥锁 */
    rwlock_t i_mapping_lock;    /* 映射锁 */

    /* LRU管理 */
    struct list_head i_lru;     /* LRU链表 */
    struct list_head i_wb_list; /* 写回链表 */

    /* 版本信息 */
    u64 i_version;             /* 版本号 */
    atomic_t i_dio_count;      /* 直接IO计数 */

    /* 安全信息 */
    void *i_security;           /* 安全模块数据 */

    /* ... 更多字段 */
};
```

### 3.2 inode操作

```c
/* 索引节点操作 */
struct inode_operations {
    /* 创建文件 */
    int (*create) (struct inode *,struct dentry *,umode_t, bool);

    /* 查找目录项 */
    struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);

    /* 创建链接 */
    int (*link) (struct dentry *,struct inode *,struct dentry *);

    /* 取消链接 */
    int (*unlink) (struct inode *,struct dentry *);

    /* 创建符号链接 */
    int (*symlink) (struct inode *,struct dentry *,const char *);

    /* 创建目录 */
    int (*mkdir) (struct inode *,struct dentry *,umode_t);

    /* 删除目录 */
    int (*rmdir) (struct inode *,struct dentry *);

    /* 创建目录项 */
    int (*mknod) (struct inode *,struct dentry *,umode_t,dev_t);

    /* 重命名 */
    int (*rename) (struct inode *, struct dentry *,
               struct inode *, struct dentry *, unsigned int);

    /* 读链接 */
    const char *(*get_link) (struct dentry *, struct inode *, struct delayed_call *);

    /* 读取目录 */
    int (*iterate) (struct file *, struct dir_context *);

    /* 权限检查 */
    int (*permission) (struct inode *, int);

    /* 设置属性 */
    int (*setattr) (struct dentry *, struct iattr *);

    /* 获取属性 */
    int (*getattr) (const struct path *, struct kstat *, u32, unsigned int);

    /* 截断文件 */
    int (*truncate) (struct inode *, loff_t);

    /* 设置ACL */
    int (*set_acl)(struct inode *, struct posix_acl *, int);

    /* 文件映射 */
    int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);

    /* 更新时间 */
    int (*update_time)(struct inode *, struct timespec64 *, int);

    /* 文件操作 */
    int (*tmpfile)(struct inode *, struct dentry *, umode_t);

    /* 属性处理 */
    int (*setxattr)(struct dentry *, const char *, const void *, size_t, int);
    ssize_t (*getxattr)(struct dentry *, const char *, void *, size_t);
    ssize_t (*listxattr)(struct dentry *, char *, size_t);
    int (*removexattr)(struct dentry *, const char *);

    /* 文件锁 */
    int (*flock)(struct file *, int, struct file_lock *);

    /* 检查可访问性 */
    int (*check_acl)(struct inode *, int);
};

/* 读取索引节点 */
struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    struct inode *inode;

    /* 从哈希表查找 */
    inode = ilookup(sb, ino);
    if (inode)
        return inode;

    /* 分配新索引节点 */
    inode = alloc_inode(sb);
    if (!inode)
        return NULL;

    /* 初始化索引节点 */
    inode->i_ino = ino;
    inode->i_sb = sb;
    inode->i_state = I_NEW;

    /* 添加到哈希表 */
    __insert_inode_hash(inode, inode->i_ino);

    return inode;
}

/* 释放索引节点 */
void iput(struct inode *inode)
{
    if (!inode)
        return;

    BUG_ON(inode->i_state & I_CLEAR);

    /* 减少引用计数 */
    if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
        /* 检查是否需要删除 */
        if (inode->i_nlink && !hlist_unhashed(&inode->i_dentry)) {
            atomic_inc(&inode->i_count);
            spin_unlock(&inode->i_lock);
            return;
        }

        /* 标记为删除 */
        inode->i_state |= I_FREEING;
        inode->i_state |= I_CLEAR;

        /* 从哈希表移除 */
        __remove_inode_hash(inode);

        spin_unlock(&inode->i_lock);

        /* 销毁索引节点 */
        if (inode->i_sb->s_op->destroy_inode)
            inode->i_sb->s_op->destroy_inode(inode);
        else
            destroy_inode(inode);
    }
}
```

## 4. 目录项管理

### 4.1 dentry结构

```c
/* 目录项 - 路径名缓存 */
struct dentry {
    /* 路径名信息 */
    struct qstr d_name;         /* 目录项名称 */
    struct hlist_bl_node d_hash; /* 哈希表节点 */
    struct dentry *d_parent;    /* 父目录项 */
    struct list_head d_child;   /* 子目录项链表 */
    struct list_head d_subdirs; /* 子目录链表 */

    /* 关联的索引节点 */
    struct inode *d_inode;      /* 关联的索引节点 */
    unsigned char d_iname[DNAME_INLINE_LEN]; /* 内联名称 */

    /* 引用计数 */
    unsigned int d_count;       /* 引用计数 */
    spinlock_t d_lock;          /* 目录项锁 */

    /* 状态标志 */
    unsigned int d_flags;       /* 目录项标志 */
    signed char d_name_len;     /* 名称长度 */

    /* 挂载信息 */
    struct vfsmount *d_mounted; /* 挂载点 */

    /* LRU管理 */
    struct list_head d_lru;     /* LRU链表 */

    /* 时间戳 */
    struct dentry_operations *d_op; /* 操作函数 */
    struct super_block *d_sb;   /* 超级块 */
    unsigned long d_time;       /* 时间戳 */
    void *d_fsdata;             /* 文件系统私有数据 */

    struct rcu_head d_rcu;      /* RCU头部 */
    struct lockref d_lockref;   /* 锁和引用计数 */
};

/* 目录项操作 */
struct dentry_operations {
    /* 验证目录项 */
    int (*d_revalidate)(struct dentry *, unsigned int);

    /* 生成哈希值 */
    int (*d_hash)(const struct dentry *, struct qstr *);

    /* 比较目录项 */
    int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);

    /* 删除目录项 */
    int (*d_delete)(const struct dentry *);

    /* 初始化目录项 */
    int (*d_init)(struct dentry *);

    /* 释放目录项 */
    void (*d_release)(struct dentry *);

    /* 清理目录项 */
    void (*d_iput)(struct dentry *, struct inode *);

    /* 自动挂载 */
    char *(*d_automount)(struct path *);

    /* 实时更新 */
    int (*d_manage)(const struct path *, bool);

    /* 断开连接 */
    void (*d_prune)(struct dentry *);
};

/* 创建目录项 */
struct dentry *d_alloc(struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry;
    char *dname;

    /* 分配目录项 */
    dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
    if (!dentry)
        return NULL;

    /* 设置名称 */
    if (name->len > DNAME_INLINE_LEN - 1) {
        dname = kmalloc(name->len + 1, GFP_KERNEL);
        if (!dname) {
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
        dentry->d_name.name = dname;
    } else {
        dentry->d_name.name = dentry->d_iname;
    }

    /* 复制名称 */
    dentry->d_name.len = name->len;
    dentry->d_name.hash = name->hash;
    memcpy(dentry->d_name.name, name->name, name->len);
    dentry->d_name.name[name->len] = 0;

    /* 初始化目录项 */
    dentry->d_count = 1;
    dentry->d_flags = 0;
    dentry->d_inode = NULL;
    dentry->d_parent = dget(parent);
    dentry->d_sb = parent->d_sb;
    dentry->d_op = NULL;
    dentry->d_fsdata = NULL;
    dentry->d_mounted = 0;
    INIT_HLIST_BL_NODE(&dentry->d_hash);
    INIT_LIST_HEAD(&dentry->d_lru);
    INIT_LIST_HEAD(&dentry->d_subdirs);
    INIT_LIST_HEAD(&dentry->d_child);
    dentry->d_lockref.count = 1;
    dentry->d_lock = __SPIN_LOCK_UNLOCKED(dentry->d_lock);
    dentry->d_time = 0;
    dentry->d_op = NULL;
    dentry->d_sb = parent->d_sb;
    dentry->d_parent = dget(parent);

    /* 添加到父目录 */
    list_add(&dentry->d_child, &parent->d_subdirs);

    return dentry;
}
```

### 4.2 路径查找

```c
/* 路径查找结构 */
struct nameidata {
    struct path path;           /* 当前路径 */
    struct qstr last;           /* 最后一个组件 */
    struct path root;           /* 根路径 */
    struct inode *inode;        /* 当前索引节点 */
    unsigned int flags;         /* 查找标志 */
    unsigned int seq;           /* 序列号 */
    int last_type;              /* 最后类型 */
    unsigned depth;             /* 深度 */
    struct file *file;          /* 文件指针 */
    struct filename *name;      /* 文件名 */
    struct nameidata *saved;    /* 保存的状态 */
    struct inode *link_inode;   /* 链接索引节点 */
};

/* 路径查找函数 */
static int link_path_walk(const char *name, struct nameidata *nd)
{
    struct path next;
    struct inode *inode;
    unsigned int lookup_flags = nd->flags;

    while (*name=='/')
        name++;
    if (!*name)
        return 0;

    for (;;) {
        struct qstr this;
        unsigned long hash;
        unsigned int c;
        int err;

        /* 获取下一个组件 */
        this.name = name;
        c = *(const unsigned char *)name;

        hash = init_name_hash();
        do {
            name++;
            hash = partial_name_hash(c, hash);
            c = *(const unsigned char *)name;
        } while (c && (c != '/'));
        this.len = name - (const char *) this.name;
        this.hash = end_name_hash(hash);

        /* 处理当前组件 */
        err = do_lookup(nd, &this, &next);
        if (err)
            break;

        /* 更新路径 */
        inode = next.dentry->d_inode;
        if (!inode) {
            err = -ENOENT;
            break;
        }

        /* 检查符号链接 */
        if (should_follow_link(inode)) {
            err = follow_link(nd, &next);
            if (err)
                break;
            continue;
        }

        /* 处理普通目录项 */
        path_to_nameidata(&next, nd);
        nd->inode = inode;
        nd->seq = read_seqcount_begin(&nd->inode->i_sequence);

        /* 检查是否到达末尾 */
        if (!*name)
            break;
    }

    return err;
}

/* 查找目录项 */
static int do_lookup(struct nameidata *nd, struct qstr *name,
             struct path *path)
{
    struct vfsmount *mnt = nd->path.mnt;
    struct dentry *dentry, *parent = nd->path.dentry;
    int status;

    /* 从缓存查找 */
    dentry = __d_lookup_rcu(parent, name, &nd->seq);
    if (!dentry) {
        dentry = d_lookup(parent, name);
        if (!dentry) {
            /* 需要实际查找 */
            status = lookup_fast(nd, name, &dentry);
            if (status)
                return status;
        }
    }

    /* 检查是否有效 */
    if (dentry->d_flags & DCACHE_OP_REVALIDATE) {
        status = d_revalidate(dentry, nd->flags);
        if (unlikely(status <= 0)) {
            if (!status)
                status = -ESTALE;
            dput(dentry);
            return status;
        }
    }

    /* 设置路径 */
    path->mnt = mnt;
    path->dentry = dentry;
    return 0;
}
```

## 5. 文件操作

### 5.1 file结构

```c
/* 文件结构 - 进程打开的文件 */
struct file {
    /* 文件信息 */
    struct path f_path;         /* 文件路径 */
    struct inode *f_inode;      /* 索引节点 */
    const struct file_operations *f_op; /* 文件操作 */

    /* 引用计数 */
    atomic_t f_count;           /* 引用计数 */
    unsigned int f_flags;       /* 文件标志 */
    fmode_t f_mode;             /* 文件模式 */

    /* 位置信息 */
    loff_t f_pos;               /* 文件位置 */
    struct fown_struct f_owner; /* 异步IO所有权 */
    unsigned int f_iocb_flags;  /* IO控制块标志 */

    /* 锁机制 */
    const struct cred *f_cred;  /* 凭证 */
    struct file_ra_state f_ra;  /* 预读状态 */

    /* 文件系统私有数据 */
    u64 f_version;             /* 版本号 */
    void *private_data;         /* 私有数据 */
    spinlock_t f_lock;          /* 文件锁 */

    /* 错误信息 */
    struct list_head f_list;    /* 文件链表 */
    struct address_space *f_mapping; /* 地址空间 */

    /* 事件通知 */
    struct fasync_struct *f_ep; /* 异步事件 */
    struct file *f_next;        /* 下一个文件 */
    struct file *f_prev;        /* 上一个文件 */
    struct path f_ppos;         /* 位置指针路径 */
};

/* 文件操作 */
struct file_operations {
    /* 读写操作 */
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);

    /* 查找操作 */
    int (*iterate) (struct file *, struct dir_context *);

    /* 同步操作 */
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);

    /* 内存映射 */
    int (*mmap) (struct file *, struct vm_area_struct *);
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);

    /* 同步操作 */
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
    int (*fasync) (int, struct file *, int);

    /* 锁操作 */
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);

    /* 检查标志 */
    int (*check_flags)(int);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
    unsigned (*mmap_capabilities)(struct file *);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
                   struct file *file_out, loff_t pos_out,
                   loff_t len, unsigned int remap_flags);
    int (*fadvise)(struct file *, loff_t, loff_t, int);
};

/* 打开文件 */
static struct file *path_openat(struct nameidata *nd,
                const struct open_flags *op,
                unsigned flags)
{
    struct file *file;
    int error;

    /* 分配文件结构 */
    file = get_empty_filp();
    if (!file)
        return ERR_PTR(-ENFILE);

    /* 设置文件标志 */
    file->f_flags = op->open_flag;
    file->f_mode = op->mode;

    /* 完成打开操作 */
    error = do_last(nd, file, op, &opened, pathname);
    if (error) {
        put_filp(file);
        return ERR_PTR(error);
    }

    return file;
}
```

### 5.2 地址空间操作

```c
/* 地址空间 */
struct address_space {
    struct inode *host;         /* 主索引节点 */
    struct radix_tree_root i_pages; /* 页面树 */
    spinlock_t tree_lock;       /* 树锁 */
    atomic_t i_mmap_writable;   /* 可写映射计数 */
    struct rb_root i_mmap;       /* VMA树 */
    unsigned long nrpages;      /* 页面数 */
    pgoff_t writeback_index;    /* 写回索引 */
    const struct address_space_operations *a_ops; /* 操作函数 */
    unsigned long flags;         /* 标志 */
    spinlock_t private_lock;    /* 私有锁 */
    struct list_head private_list; /* 私有链表 */
    void *private_data;         /* 私有数据 */
} __attribute__((aligned(sizeof(long))));

/* 地址空间操作 */
struct address_space_operations {
    /* 写页面 */
    int (*writepage)(struct page *page, struct writeback_control *wbc);

    /* 读页面 */
    int (*readpage)(struct file *, struct page *);

    /* 写页面 */
    int (*writepages)(struct address_space *, struct writeback_control *);

    /* 设置页面脏 */
    int (*set_page_dirty)(struct page *page);

    /* 读页面 */
    int (*readpages)(struct file *filp, struct address_space *mapping,
            struct list_head *pages, unsigned nr_pages);

    /* 写开始 */
    int (*write_begin)(struct file *, struct address_space *,
            loff_t pos, unsigned len, unsigned flags,
            struct page **pagep, void **fsdata);

    /* 写结束 */
    int (*write_end)(struct file *, struct address_space *,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata);

    /* 段操作 */
    ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *iter);

    /* 页面映射 */
    int (*migratepage)(struct address_space *,
            struct page *, struct page *, enum migrate_mode);

    /* 页面分离 */
    int (*launder_page)(struct page *);

    /* 页面释放 */
    int (*is_partially_uptodate)(struct page *, unsigned long, unsigned long);
    void (*is_dirty_writeback)(struct page *, bool *, bool *);
    int (*error_remove_page)(struct address_space *, struct page *);

    /* 交换操作 */
    int (*swap_activate)(struct file *);
    int (*swap_deactivate)(struct file *);
};

/* 读页面操作 */
static int filemap_read_page(struct file *file, struct page *page)
{
    struct address_space *mapping = page->mapping;
    int error;

    /* 锁定页面 */
    lock_page(page);

    /* 检查是否已经读取 */
    if (PageUptodate(page)) {
        unlock_page(page);
        return 0;
    }

    /* 调用文件系统读操作 */
    error = mapping->a_ops->readpage(file, page);
    if (error) {
        unlock_page(page);
        return error;
    }

    /* 等待读取完成 */
    if (!PageUptodate(page)) {
        unlock_page(page);
        return -EIO;
    }

    unlock_page(page);
    return 0;
}
```

## 6. 具体文件系统实现

### 6.1 EXT4文件系统

```c
/* EXT4超级块信息 */
struct ext4_super_block {
    __le32 s_inodes_count;      /* 索引节点数 */
    __le32 s_blocks_count_lo;   /* 块数（低位） */
    __le32 s_r_blocks_count_lo; /* 保留块数（低位） */
    __le32 s_free_blocks_count_lo; /* 空闲块数（低位） */
    __le32 s_free_inodes_count; /* 空闲索引节点数 */
    __le32 s_first_data_block;  /* 第一个数据块 */
    __le32 s_log_block_size;    /* 块大小对数 */
    __le32 s_log_cluster_size;  /* 簇大小对数 */
    __le32 s_blocks_per_group;  /* 每组块数 */
    __le32 s_inodes_per_group;  /* 每组索引节点数 */
    __le32 s_mtime;            /* 挂载时间 */
    __le32 s_wtime;             /* 写入时间 */
    __le16 s_mnt_count;         /* 挂载计数 */
    __le16 s_max_mnt_count;     /* 最大挂载计数 */
    __le16 s_magic;             /* 魔数 */
    __le16 s_state;             /* 文件系统状态 */
    __le16 s_errors;            /* 错误处理 */
    __le16 s_minor_rev_level;   /* 次要版本 */
    __le32 s_lastcheck;         /* 最后检查时间 */
    __le32 s_checkinterval;     /* 检查间隔 */
    __le32 s_creator_os;        /* 创建者操作系统 */
    __le32 s_rev_level;         /* 版本级别 */
    __le16 s_def_resuid;        /* 默认保留用户ID */
    __le16 s_def_resgid;        /* 默认保留组ID */
    /* ... 更多字段 */
};

/* EXT4索引节点 */
struct ext4_inode {
    __le16 i_mode;             /* 文件模式 */
    __le16 i_uid;               /* 用户ID（低位） */
    __le32 i_size_lo;          /* 文件大小（低位） */
    __le32 i_atime;            /* 访问时间 */
    __le32 i_ctime;            /* 创建时间 */
    __le32 i_mtime;            /* 修改时间 */
    __le32 i_dtime;            /* 删除时间 */
    __le16 i_gid;               /* 组ID（低位） */
    __le16 i_links_count;      /* 链接计数 */
    __le32 i_blocks_lo;        /* 块数（低位） */
    __le32 i_flags;            /* 文件标志 */
    __le32 i_file_acl_lo;      /* 文件ACL（低位） */
    __le32 i_size_high;        /* 文件大小（高位） */
    __le32 i_obso_faddr;       /* 过时碎片地址 */
    union {
        struct {
            __le32 l_i_blocks_high; /* 块数（高位） */
            __le32 l_i_file_acl_high; /* 文件ACL（高位） */
            __le32 l_i_uid_high;   /* 用户ID（高位） */
            __le32 l_i_gid_high;   /* 组ID（高位） */
            __le32 l_i_checksum_lo; /* 校验和（低位） */
            __le16 l_i_extra_isize; /* 扩展大小 */
            __le16 l_i_pad1;       /* 填充 */
            __le32 l_i_ctime_extra; /* 创建时间扩展 */
            __le32 l_i_mtime_extra; /* 修改时间扩展 */
            __le32 l_i_atime_extra; /* 访问时间扩展 */
            __le32 l_i_crtime;      /* 创建时间 */
            __le32 l_i_crtime_extra; /* 创建时间扩展 */
        } linux2;
        struct {
            __le32 h_i_translator;   /* 翻译器 */
            __le16 h_i_reserved1;    /* 保留 */
            __le16 h_i_mode_high;    /* 模式（高位） */
            __le16 h_i_uid_high;     /* 用户ID（高位） */
            __le16 h_i_gid_high;     /* 组ID（高位） */
            __le32 h_i_author;       /* 作者 */
            __le32 h_i_reserved2;    /* 保留 */
        } hurd2;
        struct {
            __le32 m_i_reserved1;     /* 保留 */
            __le32 m_i_reserved2;     /* 保留 */
            __le32 m_i_reserved3;     /* 保留 */
            __le32 m_i_reserved4;     /* 保留 */
        } masix2;
    } osd2;                      /* 操作系统相关数据 */
    __le16 i_extra_isize;       /* 扩展大小 */
    __le16 i_pad1;              /* 填充 */
    __le32 i_ctime_extra;       /* 创建时间扩展 */
    __le32 i_mtime_extra;       /* 修改时间扩展 */
    __le32 i_atime_extra;       /* 访问时间扩展 */
    __le32 i_crtime;            /* 创建时间 */
    __le32 i_crtime_extra;      /* 创建时间扩展 */
    __le32 i_version_hi;        /* 版本号（高位） */
    __le32 i_projid;            /* 项目ID */
    /* ... 更多字段 */
};

/* EXT4文件系统操作 */
static const struct super_operations ext4_sops = {
    .alloc_inode    = ext4_alloc_inode,
    .destroy_inode  = ext4_destroy_inode,
    .write_inode    = ext4_write_inode,
    .dirty_inode    = ext4_dirty_inode,
    .evict_inode    = ext4_evict_inode,
    .put_super      = ext4_put_super,
    .sync_fs        = ext4_sync_fs,
    .freeze_fs      = ext4_freeze,
    .unfreeze_fs    = ext4_unfreeze,
    .statfs         = ext4_statfs,
    .remount_fs     = ext4_remount,
    .show_options   = ext4_show_options,
};

/* EXT4索引节点操作 */
static const struct inode_operations ext4_dir_inode_operations = {
    .create         = ext4_create,
    .lookup         = ext4_lookup,
    .link           = ext4_link,
    .unlink         = ext4_unlink,
    .symlink        = ext4_symlink,
    .mkdir          = ext4_mkdir,
    .rmdir          = ext4_rmdir,
    .mknod          = ext4_mknod,
    .rename         = ext4_rename,
    .setattr        = ext4_setattr,
    .getattr        = ext4_getattr,
    .listxattr      = ext4_listxattr,
    .permission     = ext4_permission,
    .get_acl        = ext4_get_acl,
    .set_acl        = ext4_set_acl,
    .fiemap         = ext4_fiemap,
    .tmpfile        = ext4_tmpfile,
};
```

### 6.2 proc文件系统

```c
/* proc文件系统条目 */
struct proc_dir_entry {
    unsigned int low_ino;       /* 索引节点号 */
    umode_t mode;               /* 文件模式 */
    nlink_t nlink;              /* 链接数 */
    kuid_t uid;                 /* 用户ID */
    kgid_t gid;                 /* 组ID */
    loff_t size;                /* 文件大小 */
    const struct inode_operations *proc_iops; /* 索引节点操作 */
    const struct file_operations *proc_fops; /* 文件操作 */
    struct proc_dir_entry *next, *parent, *subdir; /* 链表指针 */
    void *data;                 /* 私有数据 */
    atomic_t count;             /* 引用计数 */
    struct completion *pde_unload_completion; /* 卸载完成 */
    struct list_head pde_openers; /* 打开者链表 */
    spinlock_t pde_unload_lock;  /* 卸载锁 */
    u8 namelen;                 /* 名称长度 */
    char name[];                /* 文件名 */
};

/* proc文件系统操作 */
static const struct inode_operations proc_dir_inode_operations = {
    .lookup         = proc_lookup,
    .getattr        = proc_getattr,
    .permission     = proc_permission,
    .setattr        = proc_setattr,
};

/* 创建proc条目 */
struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
                      struct proc_dir_entry *parent,
                      const struct file_operations *proc_fops,
                      void *data)
{
    struct proc_dir_entry *pde;
    struct inode *inode;
    struct dentry *dentry;

    /* 分配proc条目 */
    pde = kzalloc(sizeof(struct proc_dir_entry) + strlen(name) + 1, GFP_KERNEL);
    if (!pde)
        return NULL;

    /* 初始化条目 */
    strcpy(pde->name, name);
    pde->namelen = strlen(name);
    pde->mode = mode;
    pde->nlink = nlink;
    pde->proc_fops = proc_fops;
    pde->data = data;
    atomic_set(&pde->count, 1);
    spin_lock_init(&pde->pde_unload_lock);
    INIT_LIST_HEAD(&pde->pde_openers);

    /* 添加到父目录 */
    if (parent) {
        pde->parent = parent;
        list_add(&pde->next, &parent->subdir);
    }

    return pde;
}
```

## 7. 缓存机制

### 7.1 页面缓存

```c
/* 页面缓存结构 */
struct page_cache {
    struct radix_tree_root page_tree; /* 页面树 */
    struct address_space *mapping;   /* 地址空间 */
    spinlock_t tree_lock;            /* 树锁 */
    atomic_t nr_pages;               /* 页面数 */
    struct list_head lru;            /* LRU链表 */
};

/* 添加页面到缓存 */
void add_to_page_cache(struct page *page, struct address_space *mapping,
               pgoff_t offset, gfp_t gfp_mask)
{
    int error;

    /* 设置页面映射 */
    page->mapping = mapping;
    page->index = offset;

    /* 锁定地址空间 */
    spin_lock_irq(&mapping->tree_lock);

    /* 检查是否已存在 */
    error = radix_tree_insert(&mapping->i_pages, offset, page);
    if (unlikely(error))
        goto err;

    /* 增加页面计数 */
    mapping->nrpages++;
    __inc_zone_page_state(page, NR_FILE_PAGES);
    __inc_zone_page_state(page, NR_FILE_MAPPED);

    /* 添加到LRU链表 */
    lru_cache_add(page);

    /* 解锁 */
    spin_unlock_irq(&mapping->tree_lock);
    return;

err:
    spin_unlock_irq(&mapping->tree_lock);
    page->mapping = NULL;
}

/* 从缓存查找页面 */
struct page *find_get_page(struct address_space *mapping, pgoff_t offset)
{
    struct page *page;

    /* 从页面树查找 */
    page = radix_tree_lookup(&mapping->i_pages, offset);
    if (!page)
        return NULL;

    /* 增加引用计数 */
    if (!get_page_unless_zero(page))
        return NULL;

    return page;
}

/* 从缓存读取页面 */
int page_cache_read(struct file *file, pgoff_t offset)
{
    struct address_space *mapping = file->f_mapping;
    struct page *page;
    int error;

    /* 分配页面 */
    page = page_cache_alloc(mapping);
    if (!page)
        return -ENOMEM;

    /* 添加到缓存 */
    error = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
    if (error) {
        put_page(page);
        return error;
    }

    /* 读取页面 */
    error = mapping->a_ops->readpage(file, page);
    if (error) {
        put_page(page);
        return error;
    }

    return 0;
}
```

### 7.2 目录项缓存

```c
/* 目录项缓存管理 */
struct dentry_cache {
    struct hlist_bl_head *dentry_hashtable; /* 目录项哈希表 */
    unsigned int d_hash_shift;     /* 哈希移位 */
    struct list_head list;         /* 目录项链表 */
    struct kmem_cache *dentry_cachep; /* 目录项缓存 */
    struct {
        unsigned int nr_dentry;    /* 目录项数 */
        unsigned int nr_unused;     /* 未使用目录项数 */
        unsigned int age_limit;    /* 年龄限制 */
        unsigned int want_pages;   /* 期望页面数 */
        unsigned int dummy[2];     /* 填充 */
    } dentry_stat;
};

/* 哈希目录项 */
static inline void __d_add(struct dentry *dentry, struct inode *inode)
{
    struct inode *old_inode = dentry->d_inode;
    unsigned long hash = dentry->d_name.hash;
    struct hlist_bl_head *b = d_hash(dentry->d_parent, hash);

    /* 添加到哈希表 */
    hlist_bl_lock(b);
    __hlist_bl_add_head_rcu(&dentry->d_hash, b);
    hlist_bl_unlock(b);

    /* 设置索引节点 */
    dentry->d_inode = inode;
    if (inode) {
        hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
        dentry->d_flags &= ~DCACHE_DISCONNECTED;
    }

    /* 释放旧索引节点 */
    if (old_inode) {
        iput(old_inode);
    }
}

/* 释放目录项 */
static void __dentry_kill(struct dentry *dentry)
{
    struct dentry *parent = NULL;

    /* 从哈希表移除 */
    if (!d_unhashed(dentry))
        __d_drop(dentry);

    /* 释放索引节点 */
    if (dentry->d_inode) {
        dentry->d_inode->i_dentry.first = NULL;
        iput(dentry->d_inode);
        dentry->d_inode = NULL;
    }

    /* 释放父目录项 */
    if (dentry->d_parent != dentry) {
        parent = dentry->d_parent;
        dput(parent);
    }

    /* 释放目录项 */
    dentry->d_flags |= DCACHE_MAY_FREE;
    dentry_iput(dentry);
    dentry_stat.nr_dentry--;
}
```

## 8. 实践示例：简单文件系统实现

### 8.1 内存文件系统实现

```c
/* 简单的内存文件系统 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mpage.h>
#include <linux/swap.h>
#include <linux/slab.h>

#define RAMFS_MAGIC 0x858458f6
#define RAMFS_DEFAULT_MODE 0755

/* 内存文件系统索引节点 */
struct ramfs_inode {
    struct inode vfs_inode;        /* VFS索引节点 */
    void *data;                    /* 文件数据 */
    size_t size;                   /* 文件大小 */
};

/* 转换为内存文件系统索引节点 */
static inline struct ramfs_inode *RAMFS_I(struct inode *inode)
{
    return container_of(inode, struct ramfs_inode, vfs_inode);
}

/* 分配索引节点 */
static struct inode *ramfs_alloc_inode(struct super_block *sb)
{
    struct ramfs_inode *ri;

    ri = kzalloc(sizeof(struct ramfs_inode), GFP_KERNEL);
    if (!ri)
        return NULL;

    return &ri->vfs_inode;
}

/* 销毁索引节点 */
static void ramfs_destroy_inode(struct inode *inode)
{
    struct ramfs_inode *ri = RAMFS_I(inode);

    if (ri->data)
        kfree(ri->data);

    kfree(ri);
}

/* 读取索引节点 */
static int ramfs_readpage(struct file *file, struct page *page)
{
    struct inode *inode = page->mapping->host;
    struct ramfs_inode *ri = RAMFS_I(inode);
    char *data = kmap(page);
    size_t bytes = min_t(size_t, PAGE_SIZE, ri->size);

    /* 复制数据 */
    if (ri->data)
        memcpy(data, ri->data, bytes);
    else
        memset(data, 0, bytes);

    /* 清除剩余空间 */
    if (bytes < PAGE_SIZE)
        memset(data + bytes, 0, PAGE_SIZE - bytes);

    kunmap(page);
    SetPageUptodate(page);
    unlock_page(page);

    return 0;
}

/* 写入索引节点 */
static int ramfs_writepage(struct page *page, struct writeback_control *wbc)
{
    /* 内存文件系统不需要写入磁盘 */
    SetPageUptodate(page);
    unlock_page(page);

    return 0;
}

/* 写入开始 */
static int ramfs_write_begin(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned flags,
            struct page **pagep, void **fsdata)
{
    struct page *page;
    pgoff_t index = pos >> PAGE_SHIFT;

    page = grab_cache_page_write_begin(mapping, index, flags);
    if (!page)
        return -ENOMEM;

    *pagep = page;

    if (!PageUptodate(page) && (len != PAGE_CACHE_SIZE)) {
        unsigned from = pos & (PAGE_CACHE_SIZE - 1);
        zero_user_segments(page, 0, from, from + len, PAGE_CACHE_SIZE);
    }
    return 0;
}

/* 写入结束 */
static int ramfs_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata)
{
    struct inode *inode = mapping->host;
    struct ramfs_inode *ri = RAMFS_I(inode);
    void *data;
    unsigned from = pos & (PAGE_CACHE_SIZE - 1);
    unsigned to = from + copied;

    /* 调整数据大小 */
    if (ri->size < pos + copied) {
        data = krealloc(ri->data, pos + copied, GFP_KERNEL);
        if (!data)
            return -ENOMEM;
        ri->data = data;
        ri->size = pos + copied;
    }

    /* 复制数据 */
    if (ri->data) {
        data = kmap(page);
        memcpy(ri->data + pos, data + from, copied);
        kunmap(page);
    }

    /* 更新文件大小 */
    if (pos + copied > inode->i_size)
        i_size_write(inode, pos + copied);

    set_page_dirty(page);
    unlock_page(page);
    page_cache_release(page);

    return copied;
}

/* 地址空间操作 */
static const struct address_space_operations ramfs_aops = {
    .readpage       = ramfs_readpage,
    .writepage      = ramfs_writepage,
    .write_begin    = ramfs_write_begin,
    .write_end      = ramfs_write_end,
    .set_page_dirty = __set_page_dirty_no_writeback,
};

/* 文件操作 */
static const struct file_operations ramfs_file_operations = {
    .read_iter      = generic_file_read_iter,
    .write_iter     = generic_file_write_iter,
    .mmap           = generic_file_mmap,
    .fsync          = noop_fsync,
    .splice_read    = generic_file_splice_read,
    .splice_write   = iter_file_splice_write,
    .llseek         = generic_file_llseek,
};

/* 索引节点操作 */
static const struct inode_operations ramfs_file_inode_operations = {
    .setattr        = generic_setattr,
    .getattr        = generic_getattr,
};

/* 创建文件 */
static int ramfs_mknod(struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev)
{
    struct inode *inode = ramfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);
        error = 0;
        dir->i_mtime = dir->i_ctime = CURRENT_TIME;
    }

    return error;
}

/* 创建普通文件 */
static int ramfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
               bool excl)
{
    return ramfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

/* 创建目录 */
static int ramfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int retval = ramfs_mknod(dir, dentry, mode | S_IFDIR, 0);
    if (!retval)
        inc_nlink(dir);
    return retval;
}

/* 索引节点操作 */
static const struct inode_operations ramfs_dir_inode_operations = {
    .create         = ramfs_create,
    .lookup         = simple_lookup,
    .link           = simple_link,
    .unlink         = simple_unlink,
    .symlink        = ramfs_symlink,
    .mkdir          = ramfs_mkdir,
    .rmdir          = simple_rmdir,
    .mknod          = ramfs_mknod,
    .rename         = simple_rename,
};

/* 获取索引节点 */
struct inode *ramfs_get_inode(struct super_block *sb,
                struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);

    if (inode) {
        inode_init_owner(inode, dir, mode);
        inode->i_mapping->a_ops = &ramfs_aops;
        mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
        mapping_set_unevictable(inode->i_mapping);
        inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;

        switch (mode & S_IFMT) {
        default:
            init_special_inode(inode, mode, dev);
            break;
        case S_IFREG:
            inode->i_op = &ramfs_file_inode_operations;
            inode->i_fop = &ramfs_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &ramfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;
            inc_nlink(inode);
            break;
        case S_IFLNK:
            inode->i_op = &page_symlink_inode_operations;
            inode_nohighmem(inode);
            break;
        }
    }
    return inode;
}

/* 超级块操作 */
static const struct super_operations ramfs_ops = {
    .statfs         = simple_statfs,
    .drop_inode     = generic_delete_inode,
    .show_options   = generic_show_options,
};

/* 填充超级块 */
static int ramfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *inode;

    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_CACHE_SIZE;
    sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
    sb->s_magic = RAMFS_MAGIC;
    sb->s_op = &ramfs_ops;
    sb->s_time_gran = 1;

    /* 创建根目录 */
    inode = ramfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}

/* 挂载文件系统 */
static struct dentry *ramfs_mount(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data)
{
    return mount_nodev(fs_type, flags, data, ramfs_fill_super);
}

/* 文件系统类型 */
static struct file_system_type ramfs_fs_type = {
    .name           = "ramfs",
    .mount          = ramfs_mount,
    .kill_sb        = kill_litter_super,
    .fs_flags       = FS_USERNS_MOUNT,
};

/* 模块初始化 */
static int __init init_ramfs_fs(void)
{
    return register_filesystem(&ramfs_fs_type);
}

/* 模块退出 */
static void __exit exit_ramfs_fs(void)
{
    unregister_filesystem(&ramfs_fs_type);
}

module_init(init_ramfs_fs);
module_exit(exit_ramfs_fs);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple RAM-based filesystem");
```

## 9. 文件系统调试和监控

### 9.1 文件系统统计

```bash
# 查看文件系统信息
df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G   12G   7G  64% /
tmpfs           2G  1.2G  800M  60% /dev/shm

# 查看挂载信息
mount
/dev/sda1 on / type ext4 (rw,relatime,data=ordered)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)

# 查看文件系统统计
/proc/<pid>/mountinfo
19 26 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw
20 26 0:4 / /sys rw,nosuid,nodev,noexec,relatime shared:3 - sysfs sysfs rw
```

### 9.2 文件系统调试工具

```c
/* 文件系统调试信息 */
static void ramfs_debug_show(struct super_block *sb)
{
    struct inode *inode;
    unsigned long inodes = 0, files = 0, dirs = 0;

    /* 遍历所有索引节点 */
    spin_lock(&sb->s_inode_list_lock);
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
        inodes++;
        if (S_ISREG(inode->i_mode))
            files++;
        else if (S_ISDIR(inode->i_mode))
            dirs++;
    }
    spin_unlock(&sb->s_inode_list_lock);

    printk(KERN_INFO "RAMFS Debug:\n");
    printk(KERN_INFO "  Total inodes: %lu\n", inodes);
    printk(KERN_INFO "  Files: %lu\n", files);
    printk(KERN_INFO "  Directories: %lu\n", dirs);
}

/* 内存使用统计 */
static void ramfs_memory_stats(struct super_block *sb)
{
    struct inode *inode;
    unsigned long total_memory = 0;

    /* 计算总内存使用 */
    spin_lock(&sb->s_inode_list_lock);
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
        if (S_ISREG(inode->i_mode)) {
            struct ramfs_inode *ri = RAMFS_I(inode);
            total_memory += ri->size;
        }
    }
    spin_unlock(&sb->s_inode_list_lock);

    printk(KERN_INFO "RAMFS Memory Usage: %lu bytes\n", total_memory);
}
```

## 10. 性能优化建议

### 10.1 文件系统性能优化
- 选择合适的文件系统类型（ext4, xfs, btrfs等）
- 合理设置块大小和inode大小
- 使用noatime挂载选项减少磁盘访问
- 启用写入缓存和延迟分配

### 10.2 缓存优化
- 调整页面缓存大小
- 优化目录项缓存
- 使用SSD加速文件访问
- 考虑使用内存文件系统

### 10.3 并发优化
- 使用多个挂载点分散负载
- 优化文件锁策略
- 使用异步IO提高性能
- 考虑分布式文件系统

## 11. 总结

Linux文件系统子系统是一个复杂而灵活的系统，通过虚拟文件系统(VFS)提供统一的接口，支持多种文件系统类型。深入理解VFS架构、索引节点管理、目录项缓存和页面缓存机制，对于系统开发和性能优化至关重要。

**关键要点：**
1. VFS提供统一的文件系统抽象层
2. 超级块、索引节点、目录项是核心数据结构
3. 页面缓存和目录项缓存提高性能
4. 支持多种文件系统类型（ext4, xfs, procfs等）
5. 可以开发自定义文件系统

通过本章的学习，你将具备深入理解Linux文件系统的能力，为进一步的系统开发和优化打下坚实基础。