# SELinux与AppArmor安全策略深度分析

## 概述

SELinux (Security-Enhanced Linux) 和 AppArmor 是 Linux 内核中两个主要的强制访问控制 (MAC) 安全模块。它们通过不同的安全模型为系统提供细粒度的访问控制，保护系统免受未授权访问和恶意攻击。

## 1. SELinux 安全策略

### 1.1 SELinux 架构设计

SELinux 基于 Type Enforcement (TE) 安全模型，通过安全上下文和访问向量实现精细的访问控制。

```c
// security/selinux/include/security.h
/* SELinux 安全上下文 */
struct selinux_ctx {
    u32 user;    // 用户标识
    u32 role;    // 角色标识
    u32 type;    // 类型标识
    u32 len;     // 上下文长度
    char *str;   // 上下文字符串
};

/* SELinux 安全标识 */
struct selinux_sid {
    u32 sid;           // 安全标识符
    struct selinux_ctx ctx;  // 安全上下文
    struct hlist_node node;  // 哈希表节点
};

/* 访问向量缓存 (AVC) */
struct avc_node {
    struct hlist_node list;     // 哈希表节点
    struct avc_key key;         // 访问向量键
    struct avc_datum datum;     // 访问向量数据
    struct rcu_head rcu;        // RCU 回收头
};
```

### 1.2 Type Enforcement 安全模型

SELinux 的核心是 Type Enforcement 模型，通过类型和规则定义访问权限：

```c
// security/selinux/ss/avtab.h
/* 访问向量表 */
struct avtab_key {
    u16 source_type;    // 源类型
    u16 target_type;    // 目标类型
    u16 target_class;   // 目标类
    u16 specified;      // 指定的权限
};

struct avtab_datum {
    u32 data;           // 访问向量数据
    struct extended_perms *xperms;  // 扩展权限
};

struct avtab_node {
    struct avtab_key key;
    struct avtab_datum datum;
    struct avtab_node *next;
};

/* 访问向量表 */
struct avtab {
    struct avtab_node **htable;
    u32 nel;            // 元素数量
    u32 mask;           // 哈希掩码
};
```

### 1.3 策略数据库

SELinux 使用复杂的策略数据库存储安全规则：

```c
// security/selinux/ss/policydb.h
/* 策略数据库 */
struct policydb {
    /* 符号表 */
    struct symtab symtab[SYM_NUM];

    /* 对象上下文 */
    struct ocontext *ocontexts[OCON_NUM];

    /* 通用文件系统 */
    struct genfs *genfs;

    /* 哈希表 */
    struct hashtab *p_types_table;
    struct hashtab *p_roles_table;
    struct hashtab *p_users_table;
    struct hashtab *p_bools_table;

    /* 策略能力 */
    struct ebitmap policycaps;
    struct ebitmap permissive_map;

    /* 版本信息 */
    u32 policyvers;
    u32 target_platform;
};

/* 符号表 */
struct symtab {
    struct hashtab *table;
    u32 nprim;          // 主键数量
    char **name_to_val; // 名称到值的映射
};

/* 策略约束 */
struct role_trans {
    u32 role;           // 角色
    u32 type;           // 类型
    u32 tclass;         // 目标类
    u32 new_role;       // 新角色
    struct role_trans *next;
};
```

### 1.4 访问向量计算

SELinux 通过访问向量计算来确定权限：

```c
// security/selinux/avc.c
/* 访问向量检查 */
int avc_has_perm(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                struct common_audit_data *auditdata)
{
    struct av_decision avd;
    int rc;

    /* 获取访问决策 */
    rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, 0, &avd);

    /* 记录审计信息 */
    if (rc)
        avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata);

    return rc;
}

/* 无审计权限检查 */
int avc_has_perm_noaudit(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                        unsigned flags, struct av_decision *avd)
{
    struct avc_node *node;
    struct avc_key key;
    int rc = 0;

    /* 构造访问向量键 */
    key.ssid = ssid;
    key.tsid = tsid;
    key.tclass = tclass;

    /* 查找缓存 */
    node = avc_lookup_node(&key);
    if (node) {
        /* 缓存命中 */
        *avd = node->avd;
        rc = avc_update_node(node, requested, flags, avd);
    } else {
        /* 缓存未命中，计算访问向量 */
        rc = security_compute_av(ssid, tsid, tclass, requested, avd);
        if (!rc)
            avc_insert_node(&key, avd);
    }

    return rc;
}
```

### 1.5 SELinux 钩子实现

SELinux 通过 LSM 钩子实现访问控制：

```c
// security/selinux/hooks.c
/* 文件权限钩子 */
static int selinux_inode_permission(struct inode *inode, int mask)
{
    const struct cred *cred = current_cred();
    struct selinux_audit_data ad;
    u32 sid = cred_sid(cred);
    u32 isec_sid = inode_security_sid(inode);
    int rc;

    /* 初始化审计数据 */
    ad.type = LSM_AUDIT_DATA_INODE;
    ad.u.inode = inode;

    /* SELinux 权限检查 */
    rc = avc_has_perm(sid, isec_sid, SECCLASS_FILE,
                     file_mask_to_av(inode->i_mode, mask), &ad);

    /* 检查额外约束 */
    if (!rc && (mask & MAY_WRITE)) {
        rc = selinux_inode_need_xperm(inode, mask);
    }

    return rc;
}

/* 进程创建钩子 */
static int selinux_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    const struct cred *cred = current_cred();
    struct task_security_struct *tsec = task->security;
    u32 sid = cred_sid(cred);

    /* 分配任务安全结构 */
    tsec->osid = sid;
    tsec->sid = sid;

    /* 检查进程创建权限 */
    return avc_has_perm(sid, sid, SECCLASS_PROCESS, PROCESS__FORK, NULL);
}

/* 网络数据包钩子 */
static int selinux_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
    struct sk_security_struct *sksec = sock->sk->sk_security;
    u32 sid = current_sid();

    /* 检查网络发送权限 */
    return avc_has_perm(sid, sksec->sid, SECCLASS_SOCKET, SOCKET__WRITE, NULL);
}
```

## 2. AppArmor 安全策略

### 2.1 AppArmor 架构设计

AppArmor 基于路径名的访问控制，相比 SELinux 更易于配置和使用：

```c
// security/apparmor/include/apparmor.h
/* AppArmor 配置文件 */
struct aa_profile {
    struct aa_policybase base;
    struct aa_profile *parent;

    /* 策略数据 */
    struct aa_policydb *policy;
    struct aa_dfa *dfa;

    /* 规则集合 */
    struct aa_ruleset *rules;
    struct aa_file_rules *file_rules;
    struct aa_cap_rules *cap_rules;

    /* 状态信息 */
    u32 audit;
    u32 mode;
    u32 flags;

    /* 统计信息 */
    atomic_t label_count;
    atomic_t refcount;
};

/* 规则集合 */
struct aa_ruleset {
    struct aa_dfa *dfa;
    struct aa_file_rules *file_rules;
    struct aa_cap_rules *cap_rules;
    struct aa_net_rules *net_rules;
    struct aa_rlimit_rules *rlimit_rules;

    /* 规则标志 */
    u32 flags;

    /* 统计信息 */
    struct aa_audit_rule audit;
};

/* 文件规则 */
struct aa_file_rules {
    struct aa_dfa *dfa;
    struct aa_perm perms;
    struct aa_audit_rule audit;
};
```

### 2.2 路径名处理

AppArmor 的核心是路径名匹配和处理：

```c
// security/apparmor/path.c
/* 路径名解析 */
int aa_path_name(const struct path *path, int flags, char *buffer,
                const char **name, const char **info,
                const char **failed)
{
    struct dentry *dentry;
    int error = 0;

    *name = NULL;
    *info = NULL;
    *failed = "NULL path";

    if (!path) {
        error = -ENOENT;
        goto out;
    }

    dentry = path->dentry;
    if (!dentry) {
        error = -ENOENT;
        *failed = "no dentry";
        goto out;
    }

    /* 解析路径名 */
    error = __aa_path_name(path, flags, buffer, name, info, failed);

out:
    return error;
}

/* 内部路径名解析 */
static int __aa_path_name(const struct path *path, int flags, char *buffer,
                         const char **name, const char **info,
                         const char **failed)
{
    struct dentry *dentry = path->dentry;
    struct mount *mnt = real_mount(path->mnt);
    char *bp = buffer;
    int error = 0;

    /* 处理根目录 */
    if (dentry == mnt->mnt.mnt_root && dentry == mnt->mnt.mnt_root->d_parent) {
        *name = "/";
        goto out;
    }

    /* 构建路径名 */
    error = prepend_path(path, &mnt->mnt, buffer, &bp);
    if (error < 0)
        goto out;

    *name = bp;

out:
    return error;
}
```

### 2.3 DFA 状态机

AppArmor 使用确定性有限自动机 (DFA) 进行规则匹配：

```c
// security/apparmor/match.c
/* DFA 状态机 */
struct aa_dfa {
    u16 *table;
    u16 *states;
    u32 *flags;
    u32 *user;
    u32 start;
    u32 default_base;
    u32 next_base;
    u32 max_states;
    u32 max_perms;

    /* 状态转换表 */
    struct aa_dfa_state *states_table;

    /* 标志位 */
    unsigned int flags;
};

/* DFA 匹配 */
unsigned int aa_dfa_match(struct aa_dfa *dfa, unsigned int start,
                         const char *str)
{
    u16 *def = dfa->table + dfa->default_base;
    u16 *table = dfa->table;
    unsigned int state = start;

    /* 遍历字符串进行状态转换 */
    for (; *str; str++) {
        unsigned int next = table[state * 256 + (u8)*str];

        if (next == DFA_NOMATCH)
            break;

        state = next;
    }

    /* 返回最终状态 */
    return state;
}

/* DFA 匹配直到分隔符 */
unsigned int aa_dfa_matchn_until(struct aa_dfa *dfa, unsigned int start,
                                const char *str, int n, const char **reject)
{
    u16 *def = dfa->table + dfa->default_base;
    u16 *table = dfa->table;
    unsigned int state = start;
    const char *end = str + n;

    while (str < end && *str) {
        unsigned int next = table[state * 256 + (u8)*str];

        if (next == DFA_NOMATCH) {
            *reject = str;
            break;
        }

        state = next;
        str++;
    }

    return state;
}
```

### 2.4 AppArmor 钩子实现

AppArmor 通过 LSM 钩子实现访问控制：

```c
// security/apparmor/lsm.c
/* 文件权限钩子 */
static int apparmor_inode_permission(struct inode *inode, int mask)
{
    struct aa_label *label;
    struct path_cond cond = { };
    struct aa_profile *profile;
    int error = 0;

    /* 获取当前标签 */
    label = __begin_current_label_crit_section();

    /* 构建路径条件 */
    cond.uid = from_kuid(&init_user_ns, current_fsuid());
    cond.mode = inode->i_mode;

    /* 检查每个配置文件 */
    error = fn_for_each(label, profile,
            aa_path_perm(profile, "inode_permission", &path,
                        mask & (MAY_READ | MAY_WRITE | MAY_EXEC |
                               MAY_APPEND), &cond));

    __end_current_label_crit_section(label);

    return error;
}

/* 进程创建钩子 */
static int apparmor_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    struct aa_label *label = __begin_current_label_crit_section();
    struct aa_label *new_label = NULL;
    int error = 0;

    /* 克隆标签 */
    if (label) {
        new_label = aa_label_clone(label, GFP_KERNEL);
        if (!new_label) {
            error = -ENOMEM;
            goto out;
        }
    }

    /* 设置新任务的标签 */
    aa_set_task_label(task, new_label);

out:
    __end_current_label_crit_section(label);
    return error;
}

/* 网络数据包钩子 */
static int apparmor_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
    struct aa_label *label;
    struct aa_profile *profile;
    int error = 0;

    /* 获取当前标签 */
    label = __begin_current_label_crit_section();

    /* 检查网络权限 */
    error = fn_for_each(label, profile,
            aa_net_perm(profile, OP_SENDMSG, sock->sk->sk_family,
                       sock->type, sock->sk->sk_protocol));

    __end_current_label_crit_section(label);

    return error;
}
```

## 3. 策略管理接口

### 3.1 SELinux 策略管理

SELinux 提供丰富的策略管理接口：

```c
// security/selinux/selinuxfs.c
/* SELinux 文件系统 */
static const struct file_operations sel_checkreqprot_ops = {
    .read = sel_read_checkreqprot,
    .write = sel_write_checkreqprot,
    .llseek = generic_file_llseek,
};

static const struct file_operations sel_enforce_ops = {
    .read = sel_read_enforce,
    .write = sel_write_enforce,
    .llseek = generic_file_llseek,
};

static const struct file_operations sel_policy_ops = {
    .read = sel_read_policy,
    .write = sel_write_policy,
    .llseek = generic_file_llseek,
};

/* 策略加载 */
static ssize_t sel_write_policy(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
    struct selinux_policy *newpolicy;
    ssize_t length;
    void *data = NULL;

    /* 分配策略数据 */
    data = vmalloc(count);
    if (!data)
        return -ENOMEM;

    /* 从用户空间复制数据 */
    if (copy_from_user(data, buf, count)) {
        length = -EFAULT;
        goto out;
    }

    /* 验证策略 */
    length = security_policy_validate(data, count);
    if (length)
        goto out;

    /* 加载策略 */
    newpolicy = security_policy_load(data, count);
    if (IS_ERR(newpolicy)) {
        length = PTR_ERR(newpolicy);
        goto out;
    }

    /* 激活策略 */
    security_policy_activate(newpolicy);

    length = count;

out:
    vfree(data);
    return length;
}
```

### 3.2 AppArmor 策略管理

AppArmor 提供简化的策略管理接口：

```c
// security/apparmor/apparmorfs.c
/* AppArmor 文件系统 */
static const struct file_operations aa_fs_profile_load = {
    .write = aa_fs_profile_load,
};

static const struct file_operations aa_fs_profile_replace = {
    .write = aa_fs_profile_replace,
};

static const struct file_operations aa_fs_profile_remove = {
    .write = aa_fs_profile_remove,
};

/* 配置文件加载 */
static ssize_t aa_fs_profile_load(struct file *file, const char __user *ubuf,
                                  size_t count, loff_t *pos)
{
    struct aa_profile *profile;
    char *data;
    int error;

    /* 分配缓冲区 */
    data = kmalloc(count + 1, GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    /* 从用户空间复制数据 */
    if (copy_from_user(data, ubuf, count)) {
        error = -EFAULT;
        goto out;
    }

    data[count] = '\0';

    /* 解析配置文件 */
    profile = aa_unpack_profile(data);
    if (IS_ERR(profile)) {
        error = PTR_ERR(profile);
        goto out;
    }

    /* 加载配置文件 */
    error = aa_profile_load(profile);
    if (error)
        aa_put_profile(profile);

out:
    kfree(data);
    return error ?: count;
}
```

## 4. 性能优化

### 4.1 SELinux 性能优化

SELinux 通过多种机制优化性能：

```c
// security/selinux/avc.c
/* 访问向量缓存 */
struct avc_cache {
    struct hlist_head slots[AVC_CACHE_SLOTS];
    spinlock_t locks[AVC_CACHE_SLOTS];
    atomic_t lru_hint;
    u32 active_nodes;
};

/* 缓存节点回收 */
static void avc_reclaim_node(void)
{
    struct avc_node *node;
    struct hlist_head *head;
    struct hlist_node *n;
    unsigned long flags;
    int i;

    /* 寻找可回收的节点 */
    for (i = 0; i < AVC_CACHE_SLOTS; i++) {
        head = &avc_cache.slots[i];
        spin_lock_irqsave(&avc_cache.locks[i], flags);

        hlist_for_each_entry_safe(node, n, head, list) {
            if (atomic_read(&node->ae.used) == 0) {
                hlist_del_rcu(&node->list);
                call_rcu(&node->rhead, avc_node_free);
                avc_cache.active_nodes--;
                break;
            }
        }

        spin_unlock_irqrestore(&avc_cache.locks[i], flags);
    }
}
```

### 4.2 AppArmor 性能优化

AppArmor 通过 DFA 优化匹配性能：

```c
// security/apparmor/match.c
/* DFA 优化 */
static void aa_dfa_compress(struct aa_dfa *dfa)
{
    u16 *table = dfa->table;
    u32 *flags = dfa->flags;
    u32 i, j;

    /* 压缩状态转换表 */
    for (i = 0; i < dfa->max_states; i++) {
        for (j = 0; j < 256; j++) {
            u16 next = table[i * 256 + j];

            /* 优化相同的状态转换 */
            if (next != DFA_NOMATCH && next != DFA_DEAD) {
                table[i * 256 + j] = aa_dfa_optimize_transition(dfa, next);
            }
        }
    }

    /* 压缩标志位 */
    for (i = 0; i < dfa->max_states; i++) {
        flags[i] = aa_dfa_optimize_flags(dfa, i);
    }
}
```

## 5. 安全审计集成

### 5.1 SELinux 审计集成

SELinux 与 Linux 审计系统深度集成：

```c
// security/selinux/avc.c
/* 审计回调 */
static void avc_audit_pre_callback(struct audit_buffer *ab, void *a)
{
    struct common_audit_data *ad = a;
    struct selinux_audit_data *sad = ad->selinux_audit_data;
    u32 denied, audited;

    denied = sad->denied;
    audited = sad->audited;

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

    if (ad->type == LSM_AUDIT_DATA_INODE) {
        struct inode *inode = ad->u.inode;
        audit_log_format(ab, "ino=%lu", inode->i_ino);
    }
}

/* 记录拒绝访问 */
static void avc_audit_post_callback(struct audit_buffer *ab, void *a)
{
    struct common_audit_data *ad = a;
    struct selinux_audit_data *sad = ad->selinux_audit_data;

    if (sad->denied) {
        audit_log_format(ab, " permissive=%d", sad->result ? 0 : 1);
    }
}
```

### 5.2 AppArmor 审计集成

AppArmor 提供审计功能：

```c
// security/apparmor/audit.c
/* AppArmor 审计 */
void aa_audit_rule_known(struct audit_krule *rule, struct aa_profile *profile)
{
    struct aa_audit_rule *arule;

    arule = kmalloc(sizeof(*arule), GFP_KERNEL);
    if (!arule)
        return;

    arule->profile = profile;
    arule->type = profile->audit;

    audit_log_rule_change("apparmor", "profile_load", arule, 0);
}

/* 审计拒绝访问 */
void aa_audit_denied(struct aa_profile *profile, const char *operation,
                     const char *name, const char *info, int error)
{
    struct common_audit_data ad;
    struct aa_audit_rule arule;

    /* 初始化审计数据 */
    ad.type = LSM_AUDIT_DATA_NONE;
    ad.selinux_audit_data = NULL;

    /* 设置审计规则 */
    arule.profile = profile;
    arule.type = profile->audit;

    /* 记录审计日志 */
    audit_log_rule_change("apparmor", operation, &arule, error);
}
```

## 6. 使用示例

### 6.1 SELinux 配置示例

```bash
# SELinux 策略示例
# 定义类型
type httpd_t;
type httpd_exec_t;
type httpd_log_t;
type httpd_config_t;

# 定义角色
role system_r;
role system_r types httpd_t;

# 定义访问规则
allow httpd_t httpd_exec_t:file { read execute };
allow httpd_t httpd_log_t:file { write append };
allow httpd_t httpd_config_t:file read;

# 网络访问规则
allow httpd_t self:tcp_socket { create_bind accept };
allow httpd_t port_t:tcp_socket name_connect;

# 进程转换
domain_trans(httpd_t, httpd_exec_t, httpd_t);
```

### 6.2 AppArmor 配置示例

```bash
# AppArmor 配置文件示例
/usr/sbin/apache2 {
    # 可执行文件
    /usr/sbin/apache2 mr,

    # 配置文件
    /etc/apache2/** r,

    # 日志文件
    /var/log/apache2/* w,

    # 网络访问
    network tcp,

    # 能力
    capability setuid,
    capability setgid,
    capability net_bind_service,

    # 限制
    deny /etc/passwd r,
    deny /etc/shadow r,
}
```

## 7. 最佳实践

### 7.1 SELinux 最佳实践

1. **策略开发**
   - 使用参考策略作为基础
   - 分离策略到模块
   - 使用 m4 宏简化策略编写

2. **性能优化**
   - 启用 AVC 缓存
   - 合理设置缓存大小
   - 监控缓存命中率

3. **故障排除**
   - 使用 audit2why 分析拒绝访问
   - 启用 permissive 模式调试
   - 监控 SELinux 日志

### 7.2 AppArmor 最佳实践

1. **配置文件管理**
   - 使用 aa-genprof 生成配置文件
   - 定期更新配置文件
   - 使用 aa-complain 模式调试

2. **安全加固**
   - 最小权限原则
   - 明确的拒绝规则
   - 定期审计配置文件

3. **性能考虑**
   - 优化路径匹配规则
   - 避免过于复杂的正则表达式
   - 合理使用通配符

## 8. 总结

SELinux 和 AppArmor 作为 Linux 内核的两个主要安全模块，各自具有不同的特点和优势：

**SELinux 优势：**
- 强大的 Type Enforcement 模型
- 细粒度的访问控制
- 完整的策略管理框架
- 与审计系统的深度集成

**AppArmor 优势：**
- 简单易用的路径名匹配
- 较低的学习曲线
- 快速的策略更新
- 适合容器环境

选择哪个安全模块取决于具体的使用场景、安全需求和管理复杂度。在实际应用中，可以根据系统需求选择合适的安全策略实现。