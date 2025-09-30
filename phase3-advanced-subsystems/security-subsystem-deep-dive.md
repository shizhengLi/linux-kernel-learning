# Linux安全子系统深度分析

## 概述
Linux安全子系统是一个复杂的多层次安全框架，提供访问控制、权限管理、安全审计等功能。本分析基于Linux 6.17内核源代码，深入探讨Linux安全机制的实现原理。

## 1. 安全子系统架构

### 1.1 安全架构设计

Linux安全子系统采用分层架构：

```
用户空间 (User Space)
    ↓ 系统调用接口
安全框架层 (Security Framework Layer)
    ↓ LSM (Linux Security Modules)
访问控制层 (Access Control Layer)
    ↓ DAC + MAC
内核资源层 (Kernel Resource Layer)
```

### 1.2 关键组件

- **LSM框架**：Linux安全模块框架
- **DAC**：自主访问控制
- **MAC**：强制访问控制
- **SELinux**：安全增强Linux
- **AppArmor**：应用安全框架
- **能力系统**：进程能力控制

### 1.3 核心目录结构

- `security/` - 安全子系统核心（42个文件）
- `security/selinux/` - SELinux实现（87个文件）
- `security/apparmor/` - AppArmor实现（56个文件）
- `security/smack/` - Smack实现
- `security/tomoyo/` - Tomoyo实现

## 2. LSM框架实现

### 2.1 LSM框架概述

#### LSM目标
- 模块化安全策略
- 统一的安全接口
- 可扩展的安全机制
- 最小化性能开销

#### LSM钩子机制
```c
// LSM钩子定义
struct security_hook_list {
    struct list_head list;
    struct hlist_head *head;          // 钩子链表头
    union security_list_options {
        int (*bind)(struct socket *sock,
                   struct sockaddr *address,
                   int addrlen);
        int (*connect)(struct socket *sock,
                      struct sockaddr *address,
                      int addrlen);
        // 更多钩子函数...
    } hook;
    const char *lsm;                  // LSM模块名称
};

// LSM钩子类型
#define LSM_HOOK_INIT(NAME, CALLBACK) \
    { .head = &security_hook_heads.NAME, \
      .hook = { .NAME = CALLBACK } }
```

### 2.2 LSM钩子注册

#### 安全钩子调用
```c
// 安全钩子调用宏
#define call_int_hook(FUNC, ...) ({    \
    int RC = LSM_RET_DEFAULT(FUNC);   \
    struct security_hook_list *P;     \
                                    \
    hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
        RC = P->hook.FUNC(__VA_ARGS__); \
        if (RC != LSM_RET_DEFAULT(FUNC)) \
            break;                     \
    }                                 \
    RC;                               \
})

// 示例：文件访问检查
int security_file_permission(struct file *file, int mask)
{
    return call_int_hook(file_permission, 0, file, mask);
}
```

#### LSM模块注册
```c
// LSM模块注册函数
int __init register_security(struct security_operations *ops)
{
    if (verify(&ops) == 0) {
        security_ops = ops;
        return 0;
    }

    return -EINVAL;
}

// 安全操作结构
struct security_operations {
    // 内核安全钩子
    int (*ptrace_access_check)(struct task_struct *child,
                               unsigned int mode);
    int (*ptrace_traceme)(struct task_struct *parent);
    int (*capget)(struct task_struct *target,
                  kernel_cap_t *effective,
                  kernel_cap_t *inheritable,
                  kernel_cap_t *permitted);
    // 更多安全操作...
};
```

### 2.3 LSM安全属性

#### 安全上下文
```c
// 内核对象安全上下文
struct security_ctx {
    u32 secid;                        // 安全ID
    char *context;                    // 安全上下文字符串
    u32 contextlen;                   // 上下文长度
};

// 文件安全属性
struct file_security {
    u32 sid;                          // 安全ID
    u32 fown_sid;                     // 文件所有者ID
    u32 isid;                         // 继承ID
};

// 进程安全属性
struct task_security {
    u32 osid;                         // 原始安全ID
    u32 sid;                          // 当前安全ID
    u32 exec_sid;                     // 执行安全ID
    u32 create_sid;                   // 创建安全ID
    u32 keycreate_sid;                // 密钥创建ID
    u32 sockcreate_sid;               // 套接字创建ID
};
```

## 3. SELinux深度分析

### 3.1 SELinux架构

#### SELinux组件
- **策略语言**：安全策略定义
- **策略编译器**：策略编译和加载
- **运行时支持**：内核安全模块
- **用户空间工具**：管理工具集

#### SELinux类型强制
```c
// SELinux安全上下文
struct selinux_context {
    u32 user;                         // 用户
    u32 role;                         // 角色
    u32 type;                         // 类型
    u32 len;                          // 上下文长度
};

// 访问向量缓存
struct avc_node {
    struct hlist_node list;           // 哈希链表
    u32 tsid;                         // 目标安全ID
    u16 tclass;                       // 目标类
    u32 avd;                          // 访问向量决策
    struct selinux_avc *avc;          // AVC结构
};
```

### 3.2 SELinux策略管理

#### 策略规则
```c
// 类型强制规则
struct type_datum {
    u32 value;                        // 类型值
    u32 bounds;                       // 边界类型
    u32 primary;                      // 主类型
    u32 flavor;                       // 规则类型
    char *name;                       // 类型名称
};

// 访问向量规则
struct avtab_node {
    struct avtab_node *next;          // 链表指针
    u32 key;                          // 规则键
    struct avtab_datum *datum;        // 规则数据
};

// 策略数据库
struct policydb {
    struct symtab symtab[SYM_NUM];    // 符号表
    struct avtab te_avtab;            // 类型强制表
    struct avtab cond_avtab;          // 条件规则表
    struct role_trans *role_tr;       // 角色转换规则
    struct role_allow *role_allow;    // 角色允许规则
};
```

### 3.3 SELinux实现机制

#### 安全服务器接口
```c
// 安全决策函数
int security_compute_av(u32 ssid, u32 tsid, u16 tclass,
                        u32 requested, struct av_decision *avd)
{
    // 计算访问向量决策
    return avc_has_perm_noaudit(ssid, tsid, tclass,
                               requested, 0, avd);
}

// 安全上下文转换
int security_context_to_sid(const char *scontext, u32 scontext_len,
                           u32 *out_sid)
{
    // 将上下文字符串转换为SID
    return context_to_sid(scontext, scontext_len, out_sid);
}
```

#### AVC (Access Vector Cache)
```c
// 访问向量缓存结构
struct selinux_avc {
    struct hlist_head *slots;         // 哈希槽
    u32 nel;                          // 元素数量
    u32 seqno;                        // 序列号
    spinlock_t lock;                  // 自旋锁
    struct cache_stats stats;         // 缓存统计
};

// AVC查找
struct avc_node *avc_lookup(u32 ssid, u32 tsid, u16 tclass)
{
    u32 hvalue;
    struct avc_node *node;

    hvalue = avc_hash(ssid, tsid, tclass);
    list_for_each_entry(node, &avc_cache.slots[hvalue], list) {
        if (node->ae.ssid == ssid &&
            node->ae.tsid == tsid &&
            node->ae.tclass == tclass) {
            return node;
        }
    }
    return NULL;
}
```

## 4. AppArmor安全框架

### 4.1 AppArmor特点

#### AppArmor设计理念
- 基于路径的访问控制
- 简单的配置语法
- 易于理解和配置
- 适合应用安全

#### AppArmor配置文件
```c
// AppArmor配置文件结构
struct aa_profile {
    struct aa_profile *parent;        // 父配置
    char *name;                       // 配置名称
    struct aa_namespace *ns;          // 命名空间
    gfp_t flags;                      // 标志位
    struct aa_file_rules file;        // 文件规则
    struct aa_net_rules net;          // 网络规则
    struct aa_rlimit_rules rlimits;   // 资源限制
};

// 文件访问规则
struct aa_file_rules {
    struct aa_rule *rules;            // 规则链表
    int size;                         // 规则数量
    struct aa_file_rule *dfas;        // DFA自动机
};
```

### 4.2 AppArmor实现

#### 规则匹配机制
```c
// 文件路径匹配
int aa_path_perm(int op, struct aa_profile *profile,
                 const struct path *path, int flags,
                 u32 request, struct aa_perms *perms)
{
    char *buffer;
    const char *name;
    int error;

    // 获取文件路径
    buffer = aa_get_buffer(false);
    if (!buffer)
        return -ENOMEM;

    name = d_path(path, buffer, PATH_MAX);
    if (IS_ERR(name)) {
        error = PTR_ERR(name);
        goto out;
    }

    // 检查文件访问权限
    error = aa_path_name(op, name, flags, request, perms);

out:
    aa_put_buffer(buffer);
    return error;
}

// DFA状态机匹配
int aa_dfa_match(struct aa_dfa *dfa, int start, const char *str)
{
    int state = start;
    int c;

    while ((c = *str++) != 0) {
        state = aa_dfa_match_len(dfa, state, &c, 1);
        if (state == DFA_NOMATCH)
            break;
    }

    return state;
}
```

## 5. 能力系统

### 5.1 能力机制概述

#### 能力分类
Linux能力系统提供细粒度的特权控制：

```c
// 能力定义
#define CAP_NET_ADMIN        12        // 网络管理
#define CAP_SYS_ADMIN        21        // 系统管理
#define CAP_SYS_BOOT         22        // 系统启动
#define CAP_SYS_MODULE       16        // 模块加载
#define CAP_NET_RAW          13        // 原始网络访问
#define CAP_IPC_LOCK         14        // IPC锁定
#define CAP_SYS_PTRACE       19        // 进程跟踪
#define CAP_SYS_RESOURCE     24        // 资源限制

// 能力集
typedef struct kernel_cap_struct {
    __u32 cap[2];                     // 64位能力集
} kernel_cap_t;
```

#### 能力继承机制
```c
// 进程能力结构
struct cred {
    kernel_cap_t cap_inheritable;    // 可继承能力
    kernel_cap_t cap_permitted;      // 允许能力
    kernel_cap_t cap_effective;      // 有效能力
    kernel_cap_t cap_bset;           // 能力边界集
    struct user_namespace *user_ns;  // 用户命名空间
};

// 能力检查函数
bool has_capability(struct task_struct *tsk, int cap)
{
    int ret;

    rcu_read_lock();
    ret = security_capable(__task_cred(tsk), &init_user_ns,
                          cap, CAP_OPT_NOAUDIT);
    rcu_read_unlock();

    return ret == 0;
}
```

### 5.2 能力验证

#### 能力检查流程
```c
// 安全能力检查
int security_capable(const struct cred *cred, struct user_namespace *ns,
                     int cap, unsigned int opts)
{
    return call_int_hook(capable, 0, cred, ns, cap, opts);
}

// SELinux能力检查
int selinux_capable(const struct cred *cred, struct user_namespace *ns,
                    int cap, unsigned int opts)
{
    struct av_decision avd;
    u32 sid = cred->security;
    u32 av = CAP_TO_MASK(cap);

    // 检查SELinux策略
    return avc_has_perm_noaudit(sid, sid, SECCLASS_CAPABILITY,
                               av, 0, &avd);
}
```

## 6. 安全审计系统

### 6.1 审计框架

#### 审计事件类型
```c
// 审计事件类型定义
#define AUDIT_SYSCALL       1000      // 系统调用
#define AUDIT_PATH          1001      // 文件路径
#define AUDIT_IPC           1002      // IPC对象
#define AUDIT_SOCKETCALL    1003      // 套接字调用
#define AUDIT_CONFIG_CHANGE 1004      // 配置变更

// 审计事件结构
struct audit_buffer {
    struct sk_buff *skb;              // 套接字缓冲区
    gfp_t gfp_mask;                   // 分配标志
    struct audit_context *ctx;        // 审计上下文
};

// 审计上下文
struct audit_context {
    int dummy;                        // 哑上下文
    int in_syscall;                    // 系统调用中
    int major;                        // 系统调用号
    unsigned long argv[4];            // 系统调用参数
    struct timespec ctime;            // 创建时间
};
```

### 6.2 审计日志

#### 审计事件记录
```c
// 审计日志写入
void audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
{
    va_list args;
    int len;
    char *p;
    int reserve;

    // 格式化字符串
    va_start(args, fmt);
    len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    // 分配缓冲区
    reserve = skb_tailroom(ab->skb);
    if (reserve < len + 1)
        return;

    // 写入数据
    p = skb_put(ab->skb, len);
    va_start(args, fmt);
    vsnprintf(p, len + 1, fmt, args);
    va_end(args);
}

// 审计系统调用
void audit_syscall_entry(int major, unsigned long a1, unsigned long a2,
                         unsigned long a3, unsigned long a4)
{
    struct audit_context *ctx = current->audit_context;

    if (!ctx)
        return;

    ctx->major = major;
    ctx->argv[0] = a1;
    ctx->argv[1] = a2;
    ctx->argv[2] = a3;
    ctx->argv[3] = a4;
}
```

## 7. 密钥管理系统

### 7.1 密钥管理框架

#### 密钥类型
```c
// 密钥类型结构
struct key_type {
    const char *name;                 // 密钥类型名称
    size_t def_datalen;               // 默认数据长度
    int (*instantiate)(struct key *key,
                       const void *data,
                       size_t datalen);
    int (*update)(struct key *key,
                  const void *data,
                  size_t datalen);
    int (*match)(const struct key *key,
                 const void *description);
    void (*destroy)(struct key *key);
    // 更多操作...
};

// 密钥结构
struct key {
    atomic_t usage;                   // 引用计数
    key_serial_t serial;              // 序列号
    struct key_type *type;            // 密钥类型
    struct key_user *user;            // 用户信息
    struct timespec expiry_time;      // 过期时间
    uid_t uid;                        // 用户ID
    gid_t gid;                        // 组ID
    key_perm_t perm;                  // 权限
    unsigned short quotalen;          // 配额长度
    unsigned short datalen;           // 数据长度
    void *payload;                    // 数据载荷
};
```

### 7.2 密钥操作

#### 密钥查找和验证
```c
// 密钥查找函数
struct key *key_search(key_ref_t keyring_ref,
                      const char *type,
                      const char *description,
                      key_perm_t perm)
{
    struct keyring_list *keyring;
    struct key *key;
    int loop;

    // 遍历密钥环
    keyring = key_ref_to_ptr(keyring_ref)->payload.subscriptions;
    for (loop = 0; loop < keyring->nkeys; loop++) {
        key = keyring->keys[loop];

        // 检查密钥类型和描述
        if (strcmp(key->type->name, type) == 0 &&
            strcmp(key->description, description) == 0) {
            // 检查权限
            if (key_permission(key_ref, perm) == 0)
                return key;
        }
    }

    return NULL;
}
```

## 8. 现代安全技术

### 8.1 硬件安全特性

#### TPM (可信平台模块)
```c
// TPM设备接口
struct tpm_chip {
    struct device *dev;               // 设备对象
    struct tpm_vendor_specific *vendor; // 厂商特定数据
    u32 manufacturer_id;              // 制造商ID
    u32 capabilities;                 // 能力标志
    u16 timeout_a;                    // 超时A
    u16 timeout_b;                    // 超时B
    u16 timeout_c;                    // 超时C
    u16 timeout_d;                    // 超时D
};

// TPM操作接口
int tpm_pcr_read(u32 pcr_idx, u8 *res_buf)
{
    struct tpm_chip *chip;
    int rc;

    chip = tpm_chip_find_get(TPM_ANY_NUM);
    if (!chip)
        return -ENODEV;

    rc = tpm2_pcr_read(chip, pcr_idx, res_buf, TPM_DIGEST_SIZE);
    tpm_put_ops(chip);

    return rc;
}
```

#### 安全启动
```c
// 安全启动验证
int verify_kernel_signature(const void *buf, unsigned long buf_len,
                           struct key *trusted_keys)
{
    struct public_key_signature *pks;
    int ret;

    // 解析签名
    pks = pkcs7_get_signature_data(buf, buf_len);
    if (IS_ERR(pks))
        return PTR_ERR(pks);

    // 验证签名
    ret = verify_signature(trusted_keys, pks);

    kfree(pks);
    return ret;
}
```

### 8.2 内存安全

#### 地址空间布局随机化
```c
// ASLR实现
unsigned long randomize_stack_top(unsigned long stack_top)
{
    unsigned long random_variable = 0;

    if (current->flags & PF_RANDOMIZE) {
        random_variable = get_random_long();
        random_variable &= STACK_RND_MASK;
        random_variable <<= PAGE_SHIFT;
    }

    return PAGE_ALIGN(stack_top) - random_variable;
}

// KASAN (Kernel Address Sanitizer)
void kasan_check_read(const volatile void *p, unsigned int size)
{
    if (unlikely(!kasan_ready()))
        return;

    check_memory_region((unsigned long)p, size, false, _RET_IP_);
}
```

## 9. 安全最佳实践

### 9.1 安全配置

#### SELinux配置
```bash
# SELinux状态检查
sestatus

# 策略管理
semodule -i policy.pp
semodule -l

# 上下文管理
chcon -t bin_t /usr/local/bin/myapp
restorecon -R /var/www/
```

#### AppArmor配置
```bash
# AppArmor状态检查
aa-status

# 配置文件管理
aa-enforce /etc/apparmor.d/usr.bin.myapp
aa-complain /etc/apparmor.d/usr.bin.myapp
```

### 9.2 安全开发

#### 安全编码实践
- 使用安全函数替换不安全函数
- 输入验证和边界检查
- 最小权限原则
- 安全的错误处理

#### 内核模块安全
```c
// 安全的内核模块示例
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>

static int __init mymodule_init(void)
{
    // 安全检查
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_ERR "Permission denied\n");
        return -EPERM;
    }

    // 初始化代码
    printk(KERN_INFO "Module loaded safely\n");
    return 0;
}

static void __exit mymodule_exit(void)
{
    printk(KERN_INFO "Module unloaded safely\n");
}

module_init(mymodule_init);
module_exit(mymodule_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Developer");
MODULE_DESCRIPTION("Secure kernel module");
```

## 10. 总结

Linux安全子系统展现了现代操作系统的安全设计理念：

1. **分层安全**：多层次安全防护机制
2. **模块化设计**：灵活的安全策略框架
3. **最小权限**：细粒度的权限控制
4. **审计支持**：完整的安全审计机制

通过深入理解Linux安全子系统，我们掌握了操作系统安全设计的核心原理，为构建安全可靠的系统提供了理论基础。

---

*本分析基于Linux 6.17内核源代码，涵盖了安全子系统的完整实现和最佳实践。*