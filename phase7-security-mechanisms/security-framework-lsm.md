# Linux安全框架 - LSM深度分析

## 概述
Linux Security Modules (LSM) 是Linux内核的安全框架，提供了一个通用的、可扩展的安全机制，允许不同的安全模块插入到内核中执行访问控制决策。本文基于Linux 6.17内核源代码，深入分析LSM框架的设计原理、实现机制和扩展接口。

## 1. LSM架构设计

### 1.1 框架概述

LSM框架采用钩子(hook)机制，在内核的关键操作点插入安全检查：

```c
// include/linux/lsm_hooks.h
/* LSM钩子结构 */
struct security_hook_list {
    struct list_head list;          /* 钩子链表节点 */
    struct hlist_node *block;       /* 钩子块指针 */
    union security_list_options hook; /* 钩子函数指针 */
    const char *lsm;               /* LSM模块名称 */
};

/* 钩子类型定义 */
union security_list_options {
#define LSM_HOOK(RET, DEFAULT, NAME, ...) RET (*NAME)(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK
};

/* 钩子头结构 */
struct security_hook_heads {
    #define LSM_HOOK(RET, DEFAULT, NAME, ...) \
        struct hlist_head NAME;
    #include <linux/lsm_hook_defs.h>
    #undef LSM_HOOK
};

/* 全局钩子头定义 */
extern struct security_hook_heads security_hook_heads;
extern atomic_t lsm_active_count;
```

### 1.2 LSM初始化流程

LSM框架的初始化过程：

```c
// security/security.c
/* LSM初始化 */
void __init security_init(void)
{
    /* 初始化钩子头 */
    memset(&security_hook_heads, 0, sizeof(security_hook_heads));

    /* 初始化LSM计数器 */
    atomic_set(&lsm_active_count, 0);

    /* 注册主要LSM模块 */
    integrity_add_hooks();
    selinux_init();
    apparmor_init();
    tomoyo_init();

    /* 启用LSM */
    pr_info("LSM: security framework initialized\n");
}

/* LSM模块注册 */
void __init security_add_hooks(struct security_hook_list *hooks, int count,
                             const char *lsm)
{
    int i;

    for (i = 0; i < count; i++) {
        /* 将钩子添加到相应链表 */
        hlist_add_tail_rcu(&hooks[i].list,
                          &security_hook_heads[hooks[i].hook.offset]);
        hooks[i].lsm = lsm;
    }

    /* 更新活跃LSM计数 */
    atomic_inc(&lsm_active_count);

    pr_info("LSM: '%s' initialized\n", lsm);
}
```

## 2. LSM钩子机制

### 2.1 钩子定义与分类

LSM钩子按照功能域进行分类：

```c
// include/linux/lsm_hook_defs.h
/* 文件系统钩子 */
LSM_HOOK(int, 0, inode_permission, struct inode *inode, int mask)
LSM_HOOK(int, 0, inode_create, struct inode *dir, struct dentry *dentry,
          umode_t mode)
LSM_HOOK(int, 0, inode_link, struct dentry *old_dentry, struct inode *dir,
         struct dentry *new_dentry)
LSM_HOOK(int, 0, inode_unlink, struct inode *dir, struct dentry *dentry)
LSM_HOOK(int, 0, inode_symlink, struct inode *dir, struct dentry *dentry,
         const char *old_name)
LSM_HOOK(int, 0, inode_mkdir, struct inode *dir, struct dentry *dentry,
         umode_t mode)
LSM_HOOK(int, 0, inode_rmdir, struct inode *dir, struct dentry *dentry)
LSM_HOOK(int, 0, inode_mknod, struct inode *dir, struct dentry *dentry,
         umode_t mode, dev_t dev)
LSM_HOOK(int, 0, inode_rename, struct inode *old_dir, struct dentry *old_dentry,
         struct inode *new_dir, struct dentry *new_dentry)
LSM_HOOK(int, 0, inode_readlink, struct dentry *dentry)
LSM_HOOK(int, 0, inode_follow_link, struct dentry *dentry, struct inode *inode,
         bool rcu)
LSM_HOOK(int, 0, inode_permission, struct inode *inode, int mask)
LSM_HOOK(int, 0, inode_setattr, struct dentry *dentry, struct iattr *attr)
LSM_HOOK(int, 0, inode_getattr, const struct path *path)
LSM_HOOK(int, 0, inode_setxattr, struct dentry *dentry, const char *name,
         const void *value, size_t size, int flags)
LSM_HOOK(int, 0, inode_getxattr, struct dentry *dentry, const char *name)
LSM_HOOK(int, 0, inode_listxattr, struct dentry *dentry)
LSM_HOOK(int, 0, inode_removexattr, struct dentry *dentry, const char *name)

/* 进程管理钩子 */
LSM_HOOK(int, 0, task_alloc, struct task_struct *task, unsigned long clone_flags)
LSM_HOOK(void, LSM_RET_VOID, task_free, struct task_struct *task)
LSM_HOOK(int, 0, task_fix_setuid, struct cred *new, const struct cred *old,
         int flags)
LSM_HOOK(int, 0, task_fix_setgid, struct cred *new, const struct cred *old,
         int flags)
LSM_HOOK(int, 0, task_fix_setgroups, struct cred *new, const struct cred *old)
LSM_HOOK(int, 0, task_setpgid, struct task_struct *p, pid_t pgid)
LSM_HOOK(int, 0, task_getpgid, struct task_struct *p)
LSM_HOOK(int, 0, task_getsid, struct task_struct *p)
LSM_HOOK(void, LSM_RET_VOID, task_getsecid, struct task_struct *p, u32 *secid)
LSM_HOOK(int, 0, task_setnice, struct task_struct *p, int nice)
LSM_HOOK(int, 0, task_setioprio, struct task_struct *p, int ioprio)
LSM_HOOK(int, 0, task_getioprio, struct task_struct *p)
LSM_HOOK(int, 0, task_prlimit, const struct cred *cred,
         const struct cred *tcred, unsigned int flags)
LSM_HOOK(int, 0, task_setrlimit, struct task_struct *p, unsigned int resource,
         struct rlimit *new_rlim)
LSM_HOOK(int, 0, task_setscheduler, struct task_struct *p)
LSM_HOOK(int, 0, task_getscheduler, struct task_struct *p)
LSM_HOOK(int, 0, task_movememory, struct task_struct *p)
LSM_HOOK(int, 0, task_kill, struct task_struct *p, struct siginfo *info,
         int sig, const struct cred *cred)
LSM_HOOK(int, -EOPNOTSUPP, task_wait, struct task_struct *p)
LSM_HOOK(int, 0, task_prctl, int option, unsigned long arg2,
         unsigned long arg3, unsigned long arg4, unsigned long arg5)
LSM_HOOK(int, 0, task_to_inode, struct task_struct *p, struct inode *inode)

/* 网络安全钩子 */
LSM_HOOK(int, 0, socket_create, int family, int type, int protocol, int kern)
LSM_HOOK(int, 0, socket_post_create, struct socket *sock, int family, int type,
         int protocol, int kern)
LSM_HOOK(int, 0, socket_bind, struct socket *sock, struct sockaddr *address,
         int addrlen)
LSM_HOOK(int, 0, socket_connect, struct socket *sock, struct sockaddr *address,
         int addrlen)
LSM_HOOK(int, 0, socket_listen, struct socket *sock, int backlog)
LSM_HOOK(int, 0, socket_accept, struct socket *sock, struct socket *newsock)
LSM_HOOK(int, 0, socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
LSM_HOOK(int, 0, socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
         int flags)
LSM_HOOK(int, 0, socket_getsockname, struct socket *sock)
LSM_HOOK(int, 0, socket_getpeername, struct socket *sock)
LSM_HOOK(int, 0, socket_getsockopt, struct socket *sock, int level, int optname,
         char __user *optval, int __user *optlen)
LSM_HOOK(int, 0, socket_setsockopt, struct socket *sock, int level, int optname,
         char __user *optval, int optlen)
LSM_HOOK(int, 0, socket_shutdown, struct socket *sock, int how)
LSM_HOOK(int, 0, socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb)
LSM_HOOK(int, 0, socket_getpeersec_stream, struct socket *sock, char __user *optval,
         int __user *optlen, unsigned len)
LSM_HOOK(int, 0, socket_getpeersec_dgram, struct socket *sock,
         struct sk_buff *skb, u32 *secid)
LSM_HOOK(int, 0, sk_alloc_security, struct sock *sk, int family, gfp_t priority)
LSM_HOOK(void, LSM_RET_VOID, sk_free_security, struct sock *sk)
LSM_HOOK(void, LSM_RET_VOID, sk_clone_security, const struct sock *sk,
         struct sock *newsk)
LSM_HOOK(void, LSM_RET_VOID, sk_getsecid, const struct sock *sk, u32 *secid)
LSM_HOOK(void, LSM_RET_VOID, sock_graft, struct sock *sk, struct socket *parent)
LSM_HOOK(int, 0, inet_conn_request, struct sock *sk, struct sk_buff *skb,
         struct request_sock *req)
LSM_HOOK(int, 0, inet_csk_clone, struct sock *newsk, const struct request_sock *req)
LSM_HOOK(void, LSM_RET_VOID, inet_conn_established, struct sock *sk,
         struct sk_buff *skb)
LSM_HOOK(int, 0, secmark_relabel_packet, u32 secid)
LSM_HOOK(void, LSM_RET_VOID, secmark_refcount_inc, void)
LSM_HOOK(void, LSM_RET_VOID, secmark_refcount_dec, void)
LSM_HOOK(int, 0, req_classify_flow, const struct request_sock *req,
         struct flowi *fl)
LSM_HOOK(int, 0, flow_inherit, const struct flowi *fl, u32 secid)

/* IPC钩子 */
LSM_HOOK(int, 0, ipc_permission, struct kern_ipc_perm *ipcp, short flag)
LSM_HOOK(int, 0, ipc_getinfo, struct kern_ipc_perm *ipcp, int cmd)
LSM_HOOK(int, 0, ipc_setattr, struct kern_ipc_perm *ipcp, struct ipc_perms *perms)
LSM_HOOK(int, 0, ipc_associate, struct kern_ipc_perm *ipcp, int msqid)
LSM_HOOK(int, 0, ipc_msgque_alloc_msq, struct msg_queue *msq, int msgflg)
LSM_HOOK(int, 0, ipc_msgque_free_msq, struct msg_queue *msq)
LSM_HOOK(int, 0, ipc_msgque_alloc_msg, struct msg_msg *msg, int msqid)
LSM_HOOK(int, 0, ipc_msgque_free_msg, struct msg_msg *msg)
LSM_HOOK(int, 0, ipc_msgque_msgrcv, struct msg_queue *msq, struct msg_msg *msg,
         struct task_struct *target, long type, int mode)
LSM_HOOK(int, 0, ipc_msgque_msgrmid, struct msg_queue *msq, struct msg_msg *msg)
LSM_HOOK(int, 0, ipc_msgque_msqctl, struct msg_queue *msq, int cmd)
LSM_HOOK(int, 0, ipc_msgque_msq_notify, struct msg_queue *msq,
         struct task_struct *task)
LSM_HOOK(int, 0, ipc_shm_alloc_security, struct shmid_kernel *shp, int shmflg)
LSM_HOOK(int, 0, ipc_shm_free_security, struct shmid_kernel *shp)
LSM_HOOK(int, 0, ipc_shm_associate, struct shmid_kernel *shp, int shmflg)
LSM_HOOK(int, 0, ipc_shm_shmat, struct shmid_kernel *shp, char __user *shmaddr,
         int shmflg)
LSM_HOOK(int, 0, ipc_shm_shmdt, struct shmid_kernel *shp)
LSM_HOOK(int, 0, ipc_shm_shmctl, struct shmid_kernel *shp, int cmd)
```

### 2.2 钩子调用机制

LSM提供了统一的钩子调用接口：

```c
// security/security.c
/* 整数返回值钩子调用 */
#define call_int_hook(FUNC, IRC, ...) ({ \
    int RC = IRC; \
    do { \
        struct security_hook_list *P; \
        \
        hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
            RC = P->hook.FUNC(__VA_ARGS__); \
            if (RC != 0) \
                break; \
        } \
    } while (0); \
    RC; \
})

/* 无返回值钩子调用 */
#define call_void_hook(FUNC, ...) ({ \
    struct security_hook_list *P; \
    \
    hlist_for_each_entry(P, &security_hook_heads.FUNC, list) \
        P->hook.FUNC(__VA_ARGS__); \
})

/* 文件权限检查示例 */
int security_inode_permission(struct inode *inode, int mask)
{
    int ret;

    if (unlikely(IS_PRIVATE(inode)))
        return 0;

    /* 调用所有LSM模块的权限检查 */
    ret = call_int_hook(inode_permission, 0, inode, mask);
    if (ret)
        return ret;

    return 0;
}

/* 进程创建安全检查 */
int security_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    return call_int_hook(task_alloc, 0, task, clone_flags);
}

/* 网络套接字创建检查 */
int security_socket_create(int family, int type, int protocol, int kern)
{
    return call_int_hook(socket_create, 0, family, type, protocol, kern);
}
```

## 3. 主要LSM模块分析

### 3.1 SELinux模块

SELinux是Linux中最主要的安全模块，实现了Type Enforcement模型：

```c
// security/selinux/hooks.c
/* SELinux钩子表 */
static struct security_hook_list selinux_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, selinux_inode_permission),
    LSM_HOOK_INIT(inode_create, selinux_inode_create),
    LSM_HOOK_INIT(inode_link, selinux_inode_link),
    LSM_HOOK_INIT(inode_unlink, selinux_inode_unlink),
    LSM_HOOK_INIT(inode_symlink, selinux_inode_symlink),
    LSM_HOOK_INIT(inode_mkdir, selinux_inode_mkdir),
    LSM_HOOK_INIT(inode_rmdir, selinux_inode_rmdir),
    LSM_HOOK_INIT(inode_mknod, selinux_inode_mknod),
    LSM_HOOK_INIT(inode_rename, selinux_inode_rename),
    LSM_HOOK_INIT(inode_readlink, selinux_inode_readlink),
    LSM_HOOK_INIT(inode_follow_link, selinux_inode_follow_link),
    LSM_HOOK_INIT(inode_setattr, selinux_inode_setattr),
    LSM_HOOK_INIT(inode_getattr, selinux_inode_getattr),
    LSM_HOOK_INIT(inode_setxattr, selinux_inode_setxattr),
    LSM_HOOK_INIT(inode_getxattr, selinux_inode_getxattr),
    LSM_HOOK_INIT(inode_listxattr, selinux_inode_listxattr),
    LSM_HOOK_INIT(inode_removexattr, selinux_inode_removexattr),
    LSM_HOOK_INIT(task_alloc, selinux_task_alloc),
    LSM_HOOK_INIT(task_free, selinux_task_free),
    LSM_HOOK_INIT(task_fix_setuid, selinux_task_fix_setuid),
    LSM_HOOK_INIT(task_fix_setgid, selinux_task_fix_setgid),
    LSM_HOOK_INIT(task_fix_setgroups, selinux_task_fix_setgroups),
    LSM_HOOK_INIT(task_setpgid, selinux_task_setpgid),
    LSM_HOOK_INIT(task_getpgid, selinux_task_getpgid),
    LSM_HOOK_INIT(task_getsid, selinux_task_getsid),
    LSM_HOOK_INIT(task_getsecid, selinux_task_getsecid),
    LSM_HOOK_INIT(task_setnice, selinux_task_setnice),
    LSM_HOOK_INIT(task_setioprio, selinux_task_setioprio),
    LSM_HOOK_INIT(task_getioprio, selinux_task_getioprio),
    LSM_HOOK_INIT(task_prlimit, selinux_task_prlimit),
    LSM_HOOK_INIT(task_setrlimit, selinux_task_setrlimit),
    LSM_HOOK_INIT(task_setscheduler, selinux_task_setscheduler),
    LSM_HOOK_INIT(task_getscheduler, selinux_task_getscheduler),
    LSM_HOOK_INIT(task_movememory, selinux_task_movememory),
    LSM_HOOK_INIT(task_kill, selinux_task_kill),
    LSM_HOOK_INIT(task_wait, selinux_task_wait),
    LSM_HOOK_INIT(task_prctl, selinux_task_prctl),
    LSM_HOOK_INIT(task_to_inode, selinux_task_to_inode),
    LSM_HOOK_INIT(socket_create, selinux_socket_create),
    LSM_HOOK_INIT(socket_post_create, selinux_socket_post_create),
    LSM_HOOK_INIT(socket_bind, selinux_socket_bind),
    LSM_HOOK_INIT(socket_connect, selinux_socket_connect),
    LSM_HOOK_INIT(socket_listen, selinux_socket_listen),
    LSM_HOOK_INIT(socket_accept, selinux_socket_accept),
    LSM_HOOK_INIT(socket_sendmsg, selinux_socket_sendmsg),
    LSM_HOOK_INIT(socket_recvmsg, selinux_socket_recvmsg),
    LSM_HOOK_INIT(socket_getsockname, selinux_socket_getsockname),
    LSM_HOOK_INIT(socket_getpeername, selinux_socket_getpeername),
    LSM_HOOK_INIT(socket_getsockopt, selinux_socket_getsockopt),
    LSM_HOOK_INIT(socket_setsockopt, selinux_socket_setsockopt),
    LSM_HOOK_INIT(socket_shutdown, selinux_socket_shutdown),
    LSM_HOOK_INIT(socket_sock_rcv_skb, selinux_socket_sock_rcv_skb),
    LSM_HOOK_INIT(socket_getpeersec_stream, selinux_socket_getpeersec_stream),
    LSM_HOOK_INIT(socket_getpeersec_dgram, selinux_socket_getpeersec_dgram),
    LSM_HOOK_INIT(sk_alloc_security, selinux_sk_alloc_security),
    LSM_HOOK_INIT(sk_free_security, selinux_sk_free_security),
    LSM_HOOK_INIT(sk_clone_security, selinux_sk_clone_security),
    LSM_HOOK_INIT(sk_getsecid, selinux_sk_getsecid),
    LSM_HOOK_INIT(sock_graft, selinux_sock_graft),
    LSM_HOOK_INIT(inet_conn_request, selinux_inet_conn_request),
    LSM_HOOK_INIT(inet_csk_clone, selinux_inet_csk_clone),
    LSM_HOOK_INIT(inet_conn_established, selinux_inet_conn_established),
    LSM_HOOK_INIT(secmark_relabel_packet, selinux_secmark_relabel_packet),
    LSM_HOOK_INIT(secmark_refcount_inc, selinux_secmark_refcount_inc),
    LSM_HOOK_INIT(secmark_refcount_dec, selinux_secmark_refcount_dec),
    LSM_HOOK_INIT(req_classify_flow, selinux_req_classify_flow),
    LSM_HOOK_INIT(flow_inherit, selinux_flow_inherit),
    LSM_HOOK_INIT(ipc_permission, selinux_ipc_permission),
    LSM_HOOK_INIT(ipc_getinfo, selinux_ipc_getinfo),
    LSM_HOOK_INIT(ipc_setattr, selinux_ipc_setattr),
    LSM_HOOK_INIT(ipc_associate, selinux_ipc_associate),
    LSM_HOOK_INIT(ipc_msgque_alloc_msq, selinux_ipc_msgque_alloc_msq),
    LSM_HOOK_INIT(ipc_msgque_free_msq, selinux_ipc_msgque_free_msq),
    LSM_HOOK_INIT(ipc_msgque_alloc_msg, selinux_ipc_msgque_alloc_msg),
    LSM_HOOK_INIT(ipc_msgque_free_msg, selinux_ipc_msgque_free_msg),
    LSM_HOOK_INIT(ipc_msgque_msgrcv, selinux_ipc_msgque_msgrcv),
    LSM_HOOK_INIT(ipc_msgque_msgrmid, selinux_ipc_msgque_msgrmid),
    LSM_HOOK_INIT(ipc_msgque_msqctl, selinux_ipc_msgque_msqctl),
    LSM_HOOK_INIT(ipc_msgque_msq_notify, selinux_ipc_msgque_msq_notify),
    LSM_HOOK_INIT(ipc_shm_alloc_security, selinux_ipc_shm_alloc_security),
    LSM_HOOK_INIT(ipc_shm_free_security, selinux_ipc_shm_free_security),
    LSM_HOOK_INIT(ipc_shm_associate, selinux_ipc_shm_associate),
    LSM_HOOK_INIT(ipc_shm_shmat, selinux_ipc_shm_shmat),
    LSM_HOOK_INIT(ipc_shm_shmdt, selinux_ipc_shm_shmdt),
    LSM_HOOK_INIT(ipc_shm_shmctl, selinux_ipc_shm_shmctl),
};

/* SELinux初始化 */
static __init int selinux_init(void)
{
    /* 注册SELinux钩子 */
    security_add_hooks(selinux_hooks, ARRAY_SIZE(selinux_hooks), "selinux");

    /* 注册网络钩子 */
    selinux_nf_ip_init();
    selinux_nf_ip4_init();
    selinux_nf_ip6_init();

    /* 初始化SELinux子系统 */
    selnl_init();
    selinux_status_init();

    return 0;
}
security_initcall(selinux_init);
```

### 3.2 AppArmor模块

AppArmor是基于路径名的安全模块，提供更简单的配置方式：

```c
// security/apparmor/lsm.c
/* AppArmor钩子表 */
static struct security_hook_list apparmor_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_permission, aa_file_permission),
    LSM_HOOK_INIT(file_alloc_security, aa_file_alloc_security),
    LSM_HOOK_INIT(file_free_security, aa_file_free_security),
    LSM_HOOK_INIT(file_mmap, aa_file_mmap),
    LSM_HOOK_INIT(file_mprotect, aa_file_mprotect),
    LSM_HOOK_INIT(file_lock, aa_file_lock),
    LSM_HOOK_INIT(file_fcntl, aa_file_fcntl),
    LSM_HOOK_INIT(file_set_fowner, aa_file_set_fowner),
    LSM_HOOK_INIT(file_receive, aa_file_receive),
    LSM_HOOK_INIT(file_open, aa_file_open),
    LSM_HOOK_INIT(path_truncate, aa_path_truncate),
    LSM_HOOK_INIT(path_unlink, aa_path_unlink),
    LSM_HOOK_INIT(path_mkdir, aa_path_mkdir),
    LSM_HOOK_INIT(path_rmdir, aa_path_rmdir),
    LSM_HOOK_INIT(path_mknod, aa_path_mknod),
    LSM_HOOK_INIT(path_rename, aa_path_rename),
    LSM_HOOK_INIT(path_chmod, aa_path_chmod),
    LSM_HOOK_INIT(path_chown, aa_path_chown),
    LSM_HOOK_INIT(path_chroot, aa_path_chroot),
    LSM_HOOK_INIT(path_truncate, aa_path_truncate),
    LSM_HOOK_INIT(inode_permission, aa_inode_permission),
    LSM_HOOK_INIT(inode_create, aa_inode_create),
    LSM_HOOK_INIT(inode_link, aa_inode_link),
    LSM_HOOK_INIT(inode_unlink, aa_inode_unlink),
    LSM_HOOK_INIT(inode_symlink, aa_inode_symlink),
    LSM_HOOK_INIT(inode_mkdir, aa_inode_mkdir),
    LSM_HOOK_INIT(inode_rmdir, aa_inode_rmdir),
    LSM_HOOK_INIT(inode_mknod, aa_inode_mknod),
    LSM_HOOK_INIT(inode_rename, aa_inode_rename),
    LSM_HOOK_INIT(inode_readlink, aa_inode_readlink),
    LSM_HOOK_INIT(inode_follow_link, aa_inode_follow_link),
    LSM_HOOK_INIT(inode_permission, aa_inode_permission),
    LSM_HOOK_INIT(inode_setattr, aa_inode_setattr),
    LSM_HOOK_INIT(inode_getattr, aa_inode_getattr),
    LSM_HOOK_INIT(inode_setxattr, aa_inode_setxattr),
    LSM_HOOK_INIT(inode_getxattr, aa_inode_getattr),
    LSM_HOOK_INIT(inode_listxattr, aa_inode_listxattr),
    LSM_HOOK_INIT(inode_removexattr, aa_inode_removexattr),
    LSM_HOOK_INIT(task_alloc, aa_task_alloc),
    LSM_HOOK_INIT(task_free, aa_task_free),
    LSM_HOOK_INIT(bprm_set_creds, aa_bprm_set_creds),
    LSM_HOOK_INIT(bprm_committing_creds, aa_bprm_committing_creds),
    LSM_HOOK_INIT(bprm_committed_creds, aa_bprm_committed_creds),
    LSM_HOOK_INIT(task_fix_setuid, aa_task_fix_setuid),
    LSM_HOOK_INIT(task_fix_setgid, aa_task_fix_setgid),
    LSM_HOOK_INIT(task_fix_setgroups, aa_task_fix_setgroups),
    LSM_HOOK_INIT(task_setpgid, aa_task_setpgid),
    LSM_HOOK_INIT(task_getpgid, aa_task_getpgid),
    LSM_HOOK_INIT(task_getsid, aa_task_getsid),
    LSM_HOOK_INIT(task_getsecid, aa_task_getsecid),
    LSM_HOOK_INIT(task_setnice, aa_task_setnice),
    LSM_HOOK_INIT(task_setioprio, aa_task_setioprio),
    LSM_HOOK_INIT(task_getioprio, aa_task_getioprio),
    LSM_HOOK_INIT(task_prlimit, aa_task_prlimit),
    LSM_HOOK_INIT(task_setrlimit, aa_task_setrlimit),
    LSM_HOOK_INIT(task_setscheduler, aa_task_setscheduler),
    LSM_HOOK_INIT(task_getscheduler, aa_task_getscheduler),
    LSM_HOOK_INIT(task_movememory, aa_task_movememory),
    LSM_HOOK_INIT(task_kill, aa_task_kill),
    LSM_HOOK_INIT(task_wait, aa_task_wait),
    LSM_HOOK_INIT(task_prctl, aa_task_prctl),
    LSM_HOOK_INIT(task_to_inode, aa_task_to_inode),
    LSM_HOOK_INIT(socket_create, aa_socket_create),
    LSM_HOOK_INIT(socket_post_create, aa_socket_post_create),
    LSM_HOOK_INIT(socket_bind, aa_socket_bind),
    LSM_HOOK_INIT(socket_connect, aa_socket_connect),
    LSM_HOOK_INIT(socket_listen, aa_socket_listen),
    LSM_HOOK_INIT(socket_accept, aa_socket_accept),
    LSM_HOOK_INIT(socket_sendmsg, aa_socket_sendmsg),
    LSM_HOOK_INIT(socket_recvmsg, aa_socket_recvmsg),
    LSM_HOOK_INIT(socket_getsockname, aa_socket_getsockname),
    LSM_HOOK_INIT(socket_getpeername, aa_socket_getpeername),
    LSM_HOOK_INIT(socket_getsockopt, aa_socket_getsockopt),
    LSM_HOOK_INIT(socket_setsockopt, aa_socket_setsockopt),
    LSM_HOOK_INIT(socket_shutdown, aa_socket_shutdown),
    LSM_HOOK_INIT(sk_alloc_security, aa_sk_alloc_security),
    LSM_HOOK_INIT(sk_free_security, aa_sk_free_security),
    LSM_HOOK_INIT(sk_clone_security, aa_sk_clone_security),
    LSM_HOOK_INIT(sk_getsecid, aa_sk_getsecid),
    LSM_HOOK_INIT(sock_graft, aa_sock_graft),
    LSM_HOOK_INIT(inet_conn_request, aa_inet_conn_request),
    LSM_HOOK_INIT(inet_csk_clone, aa_inet_csk_clone),
    LSM_HOOK_INIT(inet_conn_established, aa_inet_conn_established),
    LSM_HOOK_INIT(secmark_relabel_packet, aa_secmark_relabel_packet),
    LSM_HOOK_INIT(secmark_refcount_inc, aa_secmark_refcount_inc),
    LSM_HOOK_INIT(secmark_refcount_dec, aa_secmark_refcount_dec),
    LSM_HOOK_INIT(req_classify_flow, aa_req_classify_flow),
    LSM_HOOK_INIT(flow_inherit, aa_flow_inherit),
    LSM_HOOK_INIT(ipc_permission, aa_ipc_permission),
    LSM_HOOK_INIT(ipc_getinfo, aa_ipc_getinfo),
    LSM_HOOK_INIT(ipc_setattr, aa_ipc_setattr),
    LSM_HOOK_INIT(ipc_associate, aa_ipc_associate),
    LSM_HOOK_INIT(ipc_msgque_alloc_msq, aa_ipc_msgque_alloc_msq),
    LSM_HOOK_INIT(ipc_msgque_free_msq, aa_ipc_msgque_free_msq),
    LSM_HOOK_INIT(ipc_msgque_alloc_msg, aa_ipc_msgque_alloc_msg),
    LSM_HOOK_INIT(ipc_msgque_free_msg, aa_ipc_msgque_free_msg),
    LSM_HOOK_INIT(ipc_msgque_msgrcv, aa_ipc_msgque_msgrcv),
    LSM_HOOK_INIT(ipc_msgque_msgrmid, aa_ipc_msgque_msgrmid),
    LSM_HOOK_INIT(ipc_msgque_msqctl, aa_ipc_msgque_msqctl),
    LSM_HOOK_INIT(ipc_msgque_msq_notify, aa_ipc_msgque_msq_notify),
    LSM_HOOK_INIT(ipc_shm_alloc_security, aa_ipc_shm_alloc_security),
    LSM_HOOK_INIT(ipc_shm_free_security, aa_ipc_shm_free_security),
    LSM_HOOK_INIT(ipc_shm_associate, aa_ipc_shm_associate),
    LSM_HOOK_INIT(ipc_shm_shmat, aa_ipc_shm_shmat),
    LSM_HOOK_INIT(ipc_shm_shmdt, aa_ipc_shm_shmdt),
    LSM_HOOK_INIT(ipc_shm_shmctl, aa_ipc_shm_shmctl),
};

/* AppArmor初始化 */
static int __init apparmor_init(void)
{
    int error;

    /* 初始化AppArmor子系统 */
    error = aa_setup_root_ns();
    if (error)
        return error;

    /* 注册AppArmor钩子 */
    security_add_hooks(apparmor_hooks, ARRAY_SIZE(apparmor_hooks), "apparmor");

    /* 注册文件系统钩子 */
    error = register_filesystem(&apparmor_fs_type);
    if (error)
        return error;

    /* 注册网络钩子 */
    aa_af_register();

    return 0;
}
security_initcall(apparmor_init);
```

## 4. LSM扩展机制

### 4.1 自定义LSM模块

LSM框架支持第三方安全模块的开发：

```c
// 自定义LSM模块示例
#include <linux/lsm_hooks.h>
#include <linux/security.h>

/* 自定义安全钩子实现 */
static int my_security_inode_permission(struct inode *inode, int mask)
{
    /* 自定义权限检查逻辑 */
    printk(KERN_INFO "My LSM: inode_permission called for inode %lu\n",
           inode->i_ino);

    /* 允许访问 */
    return 0;
}

static int my_security_task_alloc(struct task_struct *task,
                                  unsigned long clone_flags)
{
    /* 自定义进程分配安全检查 */
    printk(KERN_INFO "My LSM: task_alloc called for process %d\n",
           task->pid);

    return 0;
}

/* 自定义钩子表 */
static struct security_hook_list my_security_hooks[] = {
    LSM_HOOK_INIT(inode_permission, my_security_inode_permission),
    LSM_HOOK_INIT(task_alloc, my_security_task_alloc),
};

/* 模块初始化 */
static int __init my_security_init(void)
{
    /* 注册自定义安全钩子 */
    security_add_hooks(my_security_hooks, ARRAY_SIZE(my_security_hooks),
                      "my_security");

    printk(KERN_INFO "My LSM: initialized\n");
    return 0;
}

/* 模块退出 */
static void __exit my_security_exit(void)
{
    printk(KERN_INFO "My LSM: exited\n");
}

module_init(my_security_init);
module_exit(my_security_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom LSM module");
```

### 4.2 LSM栈机制

多个LSM模块可以同时工作，形成安全栈：

```c
// security/security.c
/* LSM栈初始化 */
static void __init lsm_init(void)
{
    char *lsm, *next, *sep;
    char *chosen_lsm[LSM_NAMES_MAX];
    int i = 0;
    int ret;

    /* 解析启动参数 */
    lsm = kstrdup(lsm_order, GFP_KERNEL);
    if (!lsm)
        return;

    /* 分割LSM名称 */
    sep = lsm;
    while ((next = strsep(&sep, ",")) && i < LSM_NAMES_MAX) {
        if (*next) {
            chosen_lsm[i++] = next;
        }
    }

    /* 初始化LSM模块 */
    for (i = 0; i < LSM_NAMES_MAX && chosen_lsm[i]; i++) {
        ret = lsm_init_one(chosen_lsm[i]);
        if (ret) {
            pr_err("LSM: failed to initialize %s\n", chosen_lsm[i]);
            continue;
        }
    }

    kfree(lsm);
}

/* 单个LSM模块初始化 */
static int __init lsm_init_one(const char *name)
{
    const struct lsm_info *lsm;
    int ret;

    /* 查找LSM模块 */
    lsm = lsm_find(name);
    if (!lsm) {
        pr_err("LSM: %s not found\n", name);
        return -EINVAL;
    }

    /* 初始化LSM模块 */
    ret = lsm->init();
    if (ret) {
        pr_err("LSM: failed to initialize %s\n", name);
        return ret;
    }

    pr_info("LSM: %s initialized\n", name);
    return 0;
}
```

## 5. LSM性能优化

### 5.1 热路径优化

LSM框架针对关键路径进行了优化：

```c
// security/security.c
/* 快速路径检查 */
static inline int security_fast_path(struct inode *inode, int mask)
{
    /* 快速路径：私有文件不需要安全检查 */
    if (unlikely(IS_PRIVATE(inode)))
        return 0;

    /* 快速路径：只读文件且只请求读权限 */
    if ((mask & MAY_READ) && !(mask & (MAY_WRITE | MAY_APPEND | MAY_EXEC)))
        return 0;

    return -EACCES;
}

/* 内联安全检查 */
static inline int security_inode_permission_fast(struct inode *inode, int mask)
{
    /* 快速路径 */
    if (security_fast_path(inode, mask) == 0)
        return 0;

    /* 慢速路径：调用LSM模块 */
    return security_inode_permission(inode, mask);
}
```

### 5.2 缓存机制

LSM使用缓存来减少重复计算：

```c
// security/selinux/avc.c
/* 访问向量缓存 */
struct avc_cache {
    struct hlist_head slots[AVC_CACHE_SLOTS];
    spinlock_t slots_lock[AVC_CACHE_SLOTS];
    atomic_t lru_hint;
    atomic_t active_nodes;
    u32 latest_notif;
};

/* 缓存节点 */
struct avc_node {
    struct hlist_node list;
    struct rcu_head rhead;
    struct avc_entry *ae;
    struct avc_cache *cache;
    u32 avd.seqno;
};

/* 访问向量查找 */
static struct avc_node *avc_lookup(struct avc_cache *cache, u32 ssid, u32 tsid,
                                   u16 tclass, u32 requested)
{
    struct avc_node *node;
    struct hlist_head *head;
    unsigned int hash;

    /* 计算哈希值 */
    hash = avc_hash(ssid, tsid, tclass, requested);
    head = &cache->slots[hash];

    /* 查找缓存节点 */
    hlist_for_each_entry_rcu(node, head, list) {
        if (node->ae->ssid == ssid && node->ae->tsid == tsid &&
            node->ae->tclass == tclass && node->ae->requested == requested) {
            /* 找到缓存项 */
            return node;
        }
    }

    return NULL;
}
```

## 6. 调试和监控

### 6.1 LSM调试接口

LSM提供了丰富的调试接口：

```c
// security/security.c
/* LSM状态查询 */
void security_dump_lsm_info(struct seq_file *m)
{
    const struct lsm_info *lsm;
    char *lsm_order, *next, *sep;
    int i = 0;

    /* 输出LSM顺序 */
    seq_printf(m, "LSM order: %s\n", lsm_order);

    /* 输出LSM信息 */
    lsm_order = kstrdup(lsm_order, GFP_KERNEL);
    if (!lsm_order)
        return;

    sep = lsm_order;
    while ((next = strsep(&sep, ",")) && i < LSM_NAMES_MAX) {
        if (*next) {
            lsm = lsm_find(next);
            if (lsm) {
                seq_printf(m, "  %s: %s\n", lsm->name,
                          lsm->enabled ? "enabled" : "disabled");
            }
        }
    }

    kfree(lsm_order);
}

/* LSM统计信息 */
void security_dump_lsm_stats(struct seq_file *m)
{
    struct avc_cache_stats *stats;
    int i;

    /* 输出缓存统计 */
    stats = avc_get_cache_stats();
    seq_printf(m, "AVC cache stats:\n");
    seq_printf(m, "  lookups: %u\n", stats->lookups);
    seq_printf(m, "  misses: %u\n", stats->misses);
    seq_printf(m, "  allocations: %u\n", stats->allocations);
    seq_printf(m, "  reclaims: %u\n", stats->reclaims);
    seq_printf(m, "  frees: %u\n", stats->frees);
}
```

### 6.2 审计集成

LSM与审计系统的集成：

```c
// security/selinux/avc.c
/* SELinux审计回调 */
static void avc_audit_pre_callback(struct audit_buffer *ab, void *a)
{
    struct common_audit_data *ad = a;
    struct selinux_audit_data *sad = ad->selinux_audit_data;

    /* 记录安全上下文 */
    audit_log_format(ab, "avc:  %s ", sad->denied ? "denied" : "granted");

    if (sad->ssid) {
        audit_log_format(ab, "sid=%u ", sad->ssid);
    }

    if (sad->tsid) {
        audit_log_format(ab, "tsid=%u ", sad->tsid);
    }

    if (sad->tclass) {
        audit_log_format(ab, "tclass=%u ", sad->tclass);
    }

    if (sad->requested) {
        audit_log_format(ab, "perms=%x ", sad->requested);
    }

    /* 记录对象信息 */
    if (ad->type == LSM_AUDIT_DATA_INODE) {
        struct inode *inode = ad->u.inode;
        audit_log_format(ab, "ino=%lu", inode->i_ino);
    }
}
```

## 7. 实际应用示例

### 7.1 容器安全

LSM在容器安全中的应用：

```c
// 容器安全策略示例
static int container_security_inode_permission(struct inode *inode, int mask)
{
    struct task_struct *task = current;
    struct pid_namespace *pid_ns = task_active_pid_ns(task);

    /* 检查是否在容器中 */
    if (pid_ns != &init_pid_ns) {
        /* 容器内的额外安全检查 */
        if (mask & MAY_WRITE) {
            /* 检查是否允许在容器内写入 */
            if (!container_allow_write(task, inode)) {
                return -EACCES;
            }
        }
    }

    return 0;
}

/* 容器网络隔离 */
static int container_security_socket_bind(struct socket *sock,
                                          struct sockaddr *address,
                                          int addrlen)
{
    struct task_struct *task = current;
    struct net *net = task->nsproxy->net_ns;

    /* 检查网络命名空间 */
    if (net != &init_net) {
        /* 容器网络隔离检查 */
        if (!container_allow_network_bind(task, address, addrlen)) {
            return -EACCES;
        }
    }

    return 0;
}
```

### 7.2 文件系统保护

LSM用于文件系统保护：

```c
// 关键文件系统保护
static int protected_fs_inode_permission(struct inode *inode, int mask)
{
    /* 保护关键目录 */
    if (inode->i_ino == PROC_ROOT_INO) {
        /* 保护/proc目录 */
        if (!capable(CAP_SYS_ADMIN)) {
            return -EACCES;
        }
    }

    /* 保护系统二进制文件 */
    if (inode->i_sb->s_magic == EXT_SUPER_MAGIC) {
        const char *pathname = dentry_path_raw(d_find_alias(inode),
                                             NULL, 0);
        if (pathname) {
            /* 检查是否为系统二进制文件 */
            if (is_system_binary(pathname)) {
                if (!capable(CAP_SYS_ADMIN)) {
                    return -EACCES;
                }
            }
        }
    }

    return 0;
}
```

## 8. 总结

LSM框架是Linux内核安全架构的核心，提供了：

1. **可扩展性**：支持多种安全模块的共存
2. **灵活性**：钩子机制允许在关键操作点插入安全检查
3. **性能优化**：快速路径和缓存机制减少开销
4. **标准化**：统一的安全模块接口
5. **调试支持**：丰富的调试和审计功能

理解LSM框架对于开发内核安全模块、配置安全策略和进行安全研究都具有重要意义。通过LSM，Linux内核实现了强大的安全保护能力，为现代计算环境提供了可靠的安全保障。

---

*本分析基于Linux 6.17内核源代码，涵盖了LSM安全框架的完整实现。*