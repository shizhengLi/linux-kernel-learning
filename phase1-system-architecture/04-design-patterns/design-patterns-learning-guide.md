# Linux内核设计模式学习指南

## 1. 学习路径概述

本指南提供了一个结构化的学习路径，帮助你系统地掌握Linux内核中的设计模式。学习分为四个层次，从基础概念到实际应用。

### 1.1 学习层次
1. **基础理论**：理解设计模式的基本概念
2. **内核特性**：了解内核环境对模式使用的影响
3. **模式实践**：通过实际代码学习模式应用
4. **综合应用**：在真实项目中组合使用多种模式

### 1.2 学习时间安排
- **第1周**：基础理论和内核特性
- **第2周**：创建型模式（单例、工厂、建造者）
- **第3周**：结构型模式（适配器、装饰器、外观、代理）
- **第4周**：行为型模式（观察者、策略、命令、状态）
- **第5周**：并发模式和内核特有模式
- **第6周**：综合项目实践

## 2. 学习资源

### 2.1 必读材料
- `linux-kernel-design-patterns.md` - 理论分析
- `design-patterns-practical-examples.md` - 实践示例
- 内核源代码中的实际应用

### 2.2 参考资源
- 《设计模式：可复用面向对象软件的基础》- GoF经典
- 《Linux内核设计与实现》- Robert Love
- 《Linux Device Drivers》- O'Reilly

### 2.3 工具准备
```bash
# 安装开发工具
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo apt-get install cscope ctags global

# 下载内核源代码
git clone https://github.com/torvalds/linux.git
cd linux
```

## 3. 第一层次：基础理论（第1周）

### 3.1 学习目标
- 理解设计模式的定义和分类
- 掌握面向对象设计的基本原则
- 了解设计模式的优点和局限性

### 3.2 学习内容

#### 3.2.1 设计模式基础
```c
/* 什么是设计模式？ */
/*
 * 设计模式是解决特定问题的、经过验证的解决方案模板。
 * 它们是开发人员在长期开发过程中总结出的最佳实践。
 */

/* 设计模式的要素 */
struct design_pattern_elements {
    char *name;           /* 模式名称 */
    char *problem;        /* 解决的问题 */
    char *solution;       /* 解决方案 */
    char *consequences;   /* 结果和权衡 */
};

/* 面向对象设计原则 */
class SOLID_principles {
    /* S - Single Responsibility Principle */
    /* O - Open/Closed Principle */
    /* L - Liskov Substitution Principle */
    /* I - Interface Segregation Principle */
    /* D - Dependency Inversion Principle */
};
```

#### 3.2.2 模式分类
```
创建型模式 (Creational Patterns)
├── 单例模式 (Singleton)
├── 工厂模式 (Factory)
├── 建造者模式 (Builder)
└── 原型模式 (Prototype)

结构型模式 (Structural Patterns)
├── 适配器模式 (Adapter)
├── 装饰器模式 (Decorator)
├── 外观模式 (Facade)
├── 代理模式 (Proxy)
└── 组合模式 (Composite)

行为型模式 (Behavioral Patterns)
├── 观察者模式 (Observer)
├── 策略模式 (Strategy)
├── 命令模式 (Command)
├── 状态模式 (State)
└── 模板方法模式 (Template Method)

并发模式 (Concurrency Patterns)
├── 读写锁模式 (Read-Write Lock)
├── 生产者-消费者模式 (Producer-Consumer)
└── RCU模式 (Read-Copy-Update)
```

### 3.3 实践练习

#### 3.3.1 模式识别练习
```c
/* 练习：识别内核中的单例模式 */
/* 任务：在内核源代码中找到3个单例模式的实例 */

/* 提示1：查看全局数据结构 */
/* 提示2：查找init_task */
/* 提示3：查看每CPU变量 */

/* 练习答案 */
/*
 * 1. init_task - 初始化任务的单例
 * 2. runqueues - 每CPU运行队列
 * 3. init_mm - 初始化内存描述符
 */
```

#### 3.3.2 设计原则练习
```c
/* 练习：应用单一职责原则 */
/* 任务：重构下面的代码，使其符合单一职责原则 */

/* 重构前 */
struct bad_driver {
    int (*probe)(struct device *dev);
    int (*remove)(struct device *dev);
    int (*read)(struct device *dev, char *buf, size_t len);
    int (*write)(struct device *dev, const char *buf, size_t len);
    void (*debug_print)(struct device *dev);
    int (*power_manage)(struct device *dev, int state);
};

/* 重构后 */
struct device_operations {
    int (*probe)(struct device *dev);
    int (*remove)(struct device *dev);
};

struct file_operations {
    int (*read)(struct device *dev, char *buf, size_t len);
    int (*write)(struct device *dev, const char *buf, size_t len);
};

struct debug_operations {
    void (*debug_print)(struct device *dev);
};

struct power_operations {
    int (*power_manage)(struct device *dev, int state);
};
```

## 4. 第二层次：内核特性（第1周后半部分）

### 4.1 学习目标
- 理解内核环境的特殊性
- 掌握内核中的内存管理
- 了解内核中的并发和同步机制

### 4.2 学习内容

#### 4.2.1 内核环境特性
```c
/* 内核环境的特点 */
struct kernel_environment {
    /* 无标准C库 */
    /* 栈空间有限 */
    /* 必须考虑并发 */
    /* 需要处理中断 */
    /* 内存管理特殊 */
};

/* 与用户空间的区别 */
#define KERNEL_SPACE_DIFFERENCES \
    "1. 无libc支持\n" \
    "2. 栈大小通常为8KB\n" \
    "3. 必须考虑抢占和中断\n" \
    "4. 内存分配可能失败\n" \
    "5. 必须处理错误恢复\n"
```

#### 4.2.2 内核内存管理
```c
/* 内存分配函数 */
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* 常用内存分配方式 */
void *kmalloc(size_t size, gfp_t flags);     /* 物理连续内存 */
void *vmalloc(unsigned long size);          /* 虚拟连续内存 */
void *kzalloc(size_t size, gfp_t flags);    /* 清零的kmalloc */
void *kcalloc(size_t n, size_t size, gfp_t flags); /* 数组分配 */

/* 内存释放函数 */
void kfree(const void *objp);
void vfree(const void *addr);

/* GFP标志 */
#define GFP_KERNEL    /* 普通分配，可睡眠 */
#define GFP_ATOMIC    /* 原子分配，不能睡眠 */
#define GFP_USER      /* 用户空间页分配 */
#define GFP_HIGHUSER  /* 高内存用户页分配 */
```

#### 4.2.3 并发和同步
```c
/* 自旋锁 */
#include <linux/spinlock.h>
spinlock_t my_lock;
spin_lock_init(&my_lock);
spin_lock(&my_lock);
/* 临界区 */
spin_unlock(&my_lock);

/* 互斥锁 */
#include <linux/mutex.h>
struct mutex my_mutex;
mutex_init(&my_mutex);
mutex_lock(&my_mutex);
/* 临界区 */
mutex_unlock(&my_mutex);

/* RCU */
#include <linux/rcupdate.h>
rcu_read_lock();
/* RCU读临界区 */
rcu_read_unlock();

/* 写者 */
call_rcu(&rcu_head, callback_function);
synchronize_rcu();
```

### 4.3 实践练习

#### 4.3.1 内存管理练习
```c
/* 练习：安全的内存分配 */
/* 任务：编写一个安全的内存包装函数 */

struct safe_buffer {
    void *data;
    size_t size;
    atomic_t ref_count;
};

struct safe_buffer* safe_buffer_alloc(size_t size)
{
    struct safe_buffer *buf;

    buf = kzalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf)
        return NULL;

    buf->data = kzalloc(size, GFP_KERNEL);
    if (!buf->data) {
        kfree(buf);
        return NULL;
    }

    buf->size = size;
    atomic_set(&buf->ref_count, 1);

    return buf;
}

void safe_buffer_get(struct safe_buffer *buf)
{
    if (buf)
        atomic_inc(&buf->ref_count);
}

void safe_buffer_put(struct safe_buffer *buf)
{
    if (buf && atomic_dec_and_test(&buf->ref_count)) {
        kfree(buf->data);
        kfree(buf);
    }
}
```

#### 4.3.2 并发练习
```c
/* 练习：线程安全的计数器 */
/* 任务：实现一个线程安全的计数器 */

struct safe_counter {
    atomic64_t count;
    spinlock_t lock;
};

void safe_counter_init(struct safe_counter *counter)
{
    atomic64_set(&counter->count, 0);
    spin_lock_init(&counter->lock);
}

void safe_counter_increment(struct safe_counter *counter)
{
    atomic64_inc(&counter->count);
}

int64_t safe_counter_read(struct safe_counter *counter)
{
    return atomic64_read(&counter->count);
}

void safe_counter_batch_add(struct safe_counter *counter, int64_t value)
{
    unsigned long flags;
    spin_lock_irqsave(&counter->lock, flags);
    atomic64_add(value, &counter->count);
    spin_unlock_irqrestore(&counter->lock, flags);
}
```

## 5. 第三层次：创建型模式（第2周）

### 5.1 学习目标
- 掌握单例模式的内核实现
- 理解工厂模式在驱动开发中的应用
- 学习建造者模式的内核变体

### 5.2 学习内容

#### 5.2.1 单例模式深入
```c
/* 内核中的单例模式实现 */

/* 方法1：静态全局变量 */
static struct global_state *global_instance = NULL;

struct global_state* get_global_state(void)
{
    if (!global_instance) {
        global_instance = kzalloc(sizeof(*global_instance), GFP_KERNEL);
        if (global_instance)
            global_state_init(global_instance);
    }
    return global_instance;
}

/* 方法2：每CPU单例 */
static DEFINE_PER_CPU(struct percpu_state, percpu_instance);

struct percpu_state* get_percpu_state(void)
{
    return this_cpu_ptr(&percpu_instance);
}

/* 方法3：延迟初始化 */
static struct delayed_state *delayed_instance;

struct delayed_state* get_delayed_state(void)
{
    static DEFINE_MUTEX(init_mutex);

    if (!delayed_instance) {
        mutex_lock(&init_mutex);
        if (!delayed_instance) {
            delayed_instance = kzalloc(sizeof(*delayed_instance), GFP_KERNEL);
            if (delayed_instance)
                delayed_state_init(delayed_instance);
        }
        mutex_unlock(&init_mutex);
    }
    return delayed_instance;
}
```

#### 5.2.2 工厂模式深入
```c
/* 设备驱动工厂模式 */

/* 抽象产品 */
struct abstract_device {
    const char *type;
    int (*init)(struct abstract_device *dev);
    int (*exit)(struct abstract_device *dev);
};

/* 具体产品1 */
struct uart_device {
    struct abstract_device base;
    int baud_rate;
    int data_bits;
};

/* 具体产品2 */
struct i2c_device {
    struct abstract_device base;
    int frequency;
    int address;
};

/* 工厂接口 */
struct device_factory {
    struct abstract_device* (*create_device)(const char *type, void *config);
    void (*destroy_device)(struct abstract_device *device);
};

/* 工厂实现 */
static struct abstract_device* factory_create(const char *type, void *config)
{
    if (strcmp(type, "uart") == 0) {
        return create_uart_device(config);
    } else if (strcmp(type, "i2c") == 0) {
        return create_i2c_device(config);
    }
    return NULL;
}

/* 注册工厂 */
int register_device_factory(struct device_factory *factory)
{
    /* 注册到全局工厂列表 */
    return 0;
}
```

### 5.3 实践练习

#### 5.3.1 单例模式练习
```c
/* 练习：线程安全的日志管理器 */
/* 任务：实现一个线程安全的日志管理器单例 */

struct log_manager {
    /* 日志缓冲区 */
    char *buffer;
    size_t buffer_size;
    size_t write_pos;

    /* 同步机制 */
    spinlock_t lock;
    wait_queue_head_t wait_queue;

    /* 配置 */
    int log_level;
    bool enabled;

    /* 单例实例 */
    static struct log_manager *instance;
};

/* 获取单例实例 */
struct log_manager* get_log_manager(void)
{
    static DEFINE_MUTEX(create_lock);

    if (!log_manager_instance) {
        mutex_lock(&create_lock);
        if (!log_manager_instance) {
            log_manager_instance = create_log_manager();
        }
        mutex_unlock(&create_lock);
    }

    return log_manager_instance;
}

/* 写入日志 */
int log_write(struct log_manager *log, const char *message, int level)
{
    unsigned long flags;
    int ret = 0;

    if (!log || !message || level > log->log_level)
        return -EINVAL;

    spin_lock_irqsave(&log->lock, flags);

    if (log->enabled && log->buffer) {
        size_t msg_len = strlen(message);
        size_t available = log->buffer_size - log->write_pos;

        if (msg_len < available) {
            memcpy(log->buffer + log->write_pos, message, msg_len);
            log->write_pos += msg_len;
            ret = msg_len;
        }
    }

    spin_unlock_irqrestore(&log->lock, flags);

    return ret;
}
```

## 6. 第四层次：结构型模式（第3周）

### 6.1 学习目标
- 掌握适配器模式在VFS中的应用
- 理解装饰器模式在内核中的变体
- 学习外观模式如何简化复杂操作

### 6.2 学习内容

#### 6.2.1 VFS适配器模式
```c
/* VFS适配器模式示例 */

/* 文件系统操作适配器 */
struct file_operations {
    /* 适配不同文件系统的读取操作 */
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    /* 适配不同文件系统的写入操作 */
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    /* 其他操作... */
};

/* 适配器函数 */
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_READ))
        return -EBADF;

    /* 检查是否有read方法 */
    if (!file->f_op->read && !file->f_op->read_iter)
        return -EINVAL;

    /* 安全检查 */
    ret = rw_verify_area(READ, file, pos, count);
    if (ret >= 0) {
        count = ret;
        /* 调用具体的文件系统实现 */
        if (file->f_op->read)
            ret = file->f_op->read(file, buf, count, pos);
        else
            ret = new_sync_read(file, buf, count, pos);

        if (ret > 0) {
            fsnotify_access(file);
            add_rchar(current, ret);
        }
    }

    return ret;
}
```

#### 6.2.2 装饰器模式变体
```c
/* 内核中的装饰器模式 */

/* 基础操作 */
struct base_operations {
    int (*init)(void *data);
    int (*process)(void *data);
    void (*cleanup)(void *data);
};

/* 装饰器：性能监控 */
struct perf_monitor_decorator {
    struct base_operations base;
    struct base_operations *wrapped;
    ktime_t start_time;
    ktime_t total_time;
    unsigned long call_count;
};

static int perf_monitor_init(void *data)
{
    struct perf_monitor_decorator *decorator = data;

    decorator->start_time = ktime_get();
    decorator->total_time = ktime_set(0, 0);
    decorator->call_count = 0;

    if (decorator->wrapped && decorator->wrapped->init)
        return decorator->wrapped->init(decorator->wrapped);

    return 0;
}

static int perf_monitor_process(void *data)
{
    struct perf_monitor_decorator *decorator = data;
    ktime_t start, end;
    int ret;

    start = ktime_get();

    if (decorator->wrapped && decorator->wrapped->process)
        ret = decorator->wrapped->process(decorator->wrapped);
    else
        ret = 0;

    end = ktime_get();
    decorator->total_time = ktime_add(decorator->total_time, ktime_sub(end, start));
    decorator->call_count++;

    return ret;
}
```

### 6.3 实践练习

#### 6.3.1 适配器模式练习
```c
/* 练习：设备适配器 */
/* 任务：为不同的设备创建统一的接口 */

/* 旧设备接口 */
struct legacy_device {
    int (*old_read)(struct legacy_device *dev, char *buf);
    int (*old_write)(struct legacy_device *dev, const char *buf);
};

/* 新设备接口 */
struct modern_device {
    int (*new_read)(struct modern_device *dev, char *buf, size_t len);
    int (*new_write)(struct modern_device *dev, const char *buf, size_t len);
};

/* 适配器 */
struct device_adapter {
    struct modern_device base;
    struct legacy_device *legacy;
};

static int adapter_read(struct modern_device *dev, char *buf, size_t len)
{
    struct device_adapter *adapter = container_of(dev, struct device_adapter, base);

    /* 适配新接口到旧接口 */
    if (adapter->legacy && adapter->legacy->old_read)
        return adapter->legacy->old_read(adapter->legacy, buf);

    return -ENODEV;
}

static int adapter_write(struct modern_device *dev, const char *buf, size_t len)
{
    struct device_adapter *adapter = container_of(dev, struct device_adapter, base);

    /* 适配新接口到旧接口 */
    if (adapter->legacy && adapter->legacy->old_write)
        return adapter->legacy->old_write(adapter->legacy, buf);

    return -ENODEV;
}

/* 创建适配器 */
struct modern_device* create_adapter(struct legacy_device *legacy)
{
    struct device_adapter *adapter;

    adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
    if (!adapter)
        return NULL;

    adapter->legacy = legacy;
    adapter->base.read = adapter_read;
    adapter->base.write = adapter_write;

    return &adapter->base;
}
```

## 7. 第五层次：行为型模式（第4周）

### 7.1 学习目标
- 掌握观察者模式在内核通知机制中的应用
- 理解策略模式如何优化算法选择
- 学习命令模式在异步操作中的应用

### 7.2 学习内容

#### 7.2.1 观察者模式深入
```c
/* 内核通知链机制 */

/* 通知链类型 */
#define ATOMIC_NOTIFIER_HEAD(name) \
    struct atomic_notifier_head name = \
        ATOMIC_NOTIFIER_INIT(name)

#define BLOCKING_NOTIFIER_HEAD(name) \
    struct blocking_notifier_head name = \
        BLOCKING_NOTIFIER_INIT(name)

#define RAW_NOTIFIER_HEAD(name) \
    struct raw_notifier_head name = \
        RAW_NOTIFIER_INIT(name)

/* 通知器回调函数 */
typedef int (*notifier_fn_t)(struct notifier_block *nb,
                            unsigned long action, void *data);

/* 通知器块 */
struct notifier_block {
    notifier_fn_t notifier_call;
    struct notifier_block __rcu *next;
    int priority;
};

/* 注册通知器 */
int atomic_notifier_chain_register(struct atomic_notifier_head *nh,
                                   struct notifier_block *nb)
{
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&nh->lock, flags);
    ret = notifier_chain_register(&nh->head, nb);
    spin_unlock_irqrestore(&nh->lock, flags);

    return ret;
}

/* 使用示例：内存热插拔通知 */
static int memory_callback(struct notifier_block *self,
                           unsigned long action, void *arg)
{
    struct memory_notify *mnb = arg;

    switch (action) {
    case MEM_ONLINE:
        printk(KERN_INFO "Memory online: start_pfn=%lx nr_pages=%lx\n",
               mnb->start_pfn, mnb->nr_pages);
        break;
    case MEM_OFFLINE:
        printk(KERN_INFO "Memory offline: start_pfn=%lx nr_pages=%lx\n",
               mnb->start_pfn, mnb->nr_pages);
        break;
    }

    return NOTIFY_OK;
}

static struct notifier_block memory_nb = {
    .notifier_call = memory_callback,
    .priority = 0
};

/* 注册内存热插拔通知 */
register_memory_notifier(&memory_nb);
```

#### 7.2.2 策略模式深入
```c
/* I/O调度器策略模式 */

/* 调度器策略接口 */
struct elevator_type {
    struct kobj_type ktype;
    struct elevator_ops ops;
    struct elevator_sysfs_entry *elevator_attrs;
    char elevator_name[ELV_NAME_MAX];

    /* 模块所有权 */
    struct module *elevator_owner;

    /* 调度器特性 */
    unsigned int elevator_features;

    /* 初始化和清理 */
    int (*elevator_init_fn)(struct request_queue *,
                             struct elevator_queue *);
    void (*elevator_exit_fn)(struct elevator_queue *);
};

/* 策略实例：Noop调度器 */
static struct elevator_type elevator_noop = {
    .ops = {
        .elevator_merge_fn = noop_merge,
        .elevator_dispatch_fn = noop_dispatch,
        .elevator_add_req_fn = noop_add_request,
        .elevator_former_req_fn = noop_former_request,
        .elevator_init_fn = noop_init_queue,
        .elevator_exit_fn = noop_exit_queue,
    },
    .elevator_name = "noop",
    .elevator_owner = THIS_MODULE,
};

/* 策略实例：Deadline调度器 */
static struct elevator_type elevator_deadline = {
    .ops = {
        .elevator_merge_fn = deadline_merge,
        .elevator_dispatch_fn = deadline_dispatch,
        .elevator_add_req_fn = deadline_add_request,
        .elevator_former_req_fn = noop_former_request,
        .elevator_init_fn = deadline_init_queue,
        .elevator_exit_fn = deadline_exit_queue,
    },
    .elevator_name = "deadline",
    .elevator_owner = THIS_MODULE,
};

/* 策略切换 */
int elevator_switch(struct request_queue *q, struct elevator_type *new_e)
{
    struct elevator_queue *old_elevator, *e;
    int err;

    /* 创建新的调度器实例 */
    err = new_e->elevator_init_fn(q, &e);
    if (err)
        return err;

    /* 切换调度器 */
    old_elevator = q->elevator;
    q->elevator = e;

    /* 清理旧调度器 */
    if (old_elevator)
        elevator_exit(old_elevator);

    return 0;
}
```

### 7.3 实践练习

#### 7.3.1 观察者模式练习
```c
/* 练习：自定义通知系统 */
/* 任务：实现一个自定义的事件通知系统 */

/* 事件类型 */
enum custom_event {
    EVENT_TEMPERATURE_HIGH,
    EVENT_VOLTAGE_LOW,
    EVENT_PRESSURE_NORMAL,
    EVENT_SYSTEM_ERROR,
};

/* 事件数据 */
struct event_data {
    enum custom_event type;
    int value;
    char description[128];
    struct timespec timestamp;
};

/* 观察者接口 */
struct event_observer {
    struct list_head list;
    int (*notify)(struct event_observer *observer, struct event_data *event);
    const char *name;
    void *private_data;
};

/* 通知器 */
struct event_notifier {
    struct list_head observers;
    spinlock_t lock;
};

/* 注册观察者 */
int event_notifier_register(struct event_notifier *notifier,
                           struct event_observer *observer)
{
    unsigned long flags;

    if (!notifier || !observer || !observer->notify)
        return -EINVAL;

    spin_lock_irqsave(&notifier->lock, flags);
    list_add_tail(&observer->list, &notifier->observers);
    spin_unlock_irqrestore(&notifier->lock, flags);

    printk(KERN_INFO "EventNotifier: Observer '%s' registered\n", observer->name);
    return 0;
}

/* 发送事件 */
void event_notifier_send(struct event_notifier *notifier,
                        enum custom_event type, int value,
                        const char *description)
{
    struct event_data event;
    struct event_observer *observer;
    unsigned long flags;

    /* 准备事件数据 */
    event.type = type;
    event.value = value;
    event.timestamp = current_kernel_time();
    if (description)
        strlcpy(event.description, description, sizeof(event.description));

    printk(KERN_INFO "EventNotifier: Sending event type=%d, value=%d\n",
           type, value);

    /* 通知所有观察者 */
    spin_lock_irqsave(&notifier->lock, flags);
    list_for_each_entry(observer, &notifier->observers, list) {
        observer->notify(observer, &event);
    }
    spin_unlock_irqrestore(&notifier->lock, flags);
}
```

## 8. 第六层次：并发模式和内核特有模式（第5周）

### 8.1 学习目标
- 掌握RCU模式的原理和应用
- 理解读写锁模式的实现
- 学习内核特有模式如Kobject模式

### 8.2 学习内容

#### 8.2.1 RCU模式深入
```c
/* RCU (Read-Copy-Update) 模式 */

/* RCU读操作 */
void rcu_read_example(void)
{
    struct data_struct *data;

    rcu_read_lock();
    data = rcu_dereference(global_data_ptr);

    /* 安全地读取数据 */
    if (data) {
        process_data(data);
    }

    rcu_read_unlock();
}

/* RCU写操作 */
void rcu_write_example(struct data_struct *new_data)
{
    struct data_struct *old_data;

    /* 准备新数据 */
    new_data = create_new_data();

    /* 原子替换指针 */
    old_data = rcu_replace_pointer(global_data_ptr, new_data, GFP_KERNEL);

    /* 延迟释放旧数据 */
    if (old_data) {
        call_rcu(&old_data->rcu, data_free_callback);
    }
}

/* RCU回调函数 */
void data_free_callback(struct rcu_head *rcu)
{
    struct data_struct *data = container_of(rcu, struct data_struct, rcu);

    /* 安全地释放数据 */
    kfree(data);
}
```

#### 8.2.2 Kobject模式
```c
/* Kobject模式实现 */

/* 内核对象 */
struct my_kobject {
    struct kobject kobj;
    int my_value;
    char my_name[32];
};

/* Kobject释放函数 */
void my_kobject_release(struct kobject *kobj)
{
    struct my_kobject *my_obj = container_of(kobj, struct my_kobject, kobj);

    printk(KERN_INFO "MyKobject: Releasing object '%s'\n", my_obj->my_name);
    kfree(my_obj);
}

/* Kobject属性 */
struct kobj_attribute my_attribute = __ATTR(my_value, 0664, my_value_show, my_value_store);

/* 显示属性值 */
ssize_t my_value_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct my_kobject *my_obj = container_of(kobj, struct my_kobject, kobj);

    return sprintf(buf, "%d\n", my_obj->my_value);
}

/* 设置属性值 */
ssize_t my_value_store(struct kobject *kobj, struct kobj_attribute *attr,
                       const char *buf, size_t count)
{
    struct my_kobject *my_obj = container_of(kobj, struct my_kobject, kobj);
    int value;

    if (sscanf(buf, "%d", &value) == 1) {
        my_obj->my_value = value;
        return count;
    }

    return -EINVAL;
}

/* 创建Kobject */
struct my_kobject* create_my_kobject(const char *name, int value)
{
    struct my_kobject *my_obj;
    int ret;

    my_obj = kzalloc(sizeof(*my_obj), GFP_KERNEL);
    if (!my_obj)
        return NULL;

    /* 初始化Kobject */
    kobject_init(&my_obj->kobj, &my_ktype);

    /* 设置名称 */
    my_obj->my_value = value;
    strlcpy(my_obj->my_name, name, sizeof(my_obj->my_name));

    /* 添加到sysfs */
    ret = kobject_add(&my_obj->kobj, NULL, "%s", name);
    if (ret) {
        kobject_put(&my_obj->kobj);
        return NULL;
    }

    /* 创建属性文件 */
    ret = sysfs_create_file(&my_obj->kobj, &my_attribute.attr);
    if (ret) {
        kobject_put(&my_obj->kobj);
        return NULL;
    }

    return my_obj;
}
```

### 8.3 实践练习

#### 8.3.1 RCU模式练习
```c
/* 练习：RCU保护的链表 */
/* 任务：实现一个RCU保护的链表 */

/* 链表节点 */
struct rcu_list_node {
    struct list_head list;
    struct rcu_head rcu;
    int data;
    char name[32];
};

/* 链表结构 */
struct rcu_list {
    struct list_head head;
    struct rw_semaphore lock;
};

/* 初始化链表 */
void rcu_list_init(struct rcu_list *list)
{
    INIT_LIST_HEAD(&list->head);
    init_rwsem(&list->lock);
}

/* 查找节点（读操作） */
struct rcu_list_node* rcu_list_find(struct rcu_list *list, const char *name)
{
    struct rcu_list_node *node;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &list->head, list) {
        if (strcmp(node->name, name) == 0) {
            rcu_read_unlock();
            return node;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/* 添加节点（写操作） */
int rcu_list_add(struct rcu_list *list, const char *name, int data)
{
    struct rcu_list_node *new_node;

    new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node)
        return -ENOMEM;

    new_node->data = data;
    strlcpy(new_node->name, name, sizeof(new_node->name));

    down_write(&list->lock);
    list_add_rcu(&new_node->list, &list->head);
    up_write(&list->lock);

    return 0;
}

/* 删除节点（写操作） */
void rcu_list_remove(struct rcu_list *list, const char *name)
{
    struct rcu_list_node *node, *tmp;

    down_write(&list->lock);
    list_for_each_entry_safe(node, tmp, &list->head, list) {
        if (strcmp(node->name, name) == 0) {
            list_del_rcu(&node->list);
            up_write(&list->lock);

            /* RCU延迟释放 */
            call_rcu(&node->rcu, rcu_list_free_node);
            return;
        }
    }
    up_write(&list->lock);
}

/* RCU释放函数 */
void rcu_list_free_node(struct rcu_head *rcu)
{
    struct rcu_list_node *node = container_of(rcu, struct rcu_list_node, rcu);
    kfree(node);
}
```

## 9. 第七层次：综合项目实践（第6周）

### 9.1 项目概述
创建一个综合性的内核模块，展示多种设计模式的组合使用。

### 9.2 项目要求

#### 9.2.1 功能需求
- 实现一个虚拟设备管理器
- 支持设备的动态添加和删除
- 提供设备事件通知机制
- 支持多种设备类型
- 实现性能监控和统计

#### 9.2.2 设计模式要求
- 使用工厂模式创建设备
- 使用观察者模式实现事件通知
- 使用单例模式管理全局状态
- 使用策略模式实现不同的设备操作
- 使用装饰器模式添加性能监控

### 9.3 项目实现

#### 9.3.1 项目结构
```c
/* 虚拟设备管理器 */
struct virtual_device_manager {
    /* 单例实例 */
    static struct virtual_device_manager *instance;

    /* 设备工厂 */
    struct device_factory *factory;

    /* 事件通知器 */
    struct event_notifier *notifier;

    /* 设备列表 */
    struct list_head devices;
    struct rw_semaphore devices_lock;

    /* 性能监控 */
    struct perf_monitor *perf_monitor;

    /* 配置 */
    struct device_config config;
};

/* 虚拟设备接口 */
struct virtual_device {
    struct list_head list;
    char name[32];
    int device_id;
    enum device_type type;

    /* 设备操作 */
    struct device_operations *ops;

    /* 私有数据 */
    void *private_data;
};
```

#### 9.3.2 完整实现步骤

1. **设计架构**：确定使用的模式和接口
2. **实现基础组件**：工厂、观察者、单例等
3. **实现设备管理**：添加、删除、查找设备
4. **实现事件系统**：注册、通知事件
5. **添加性能监控**：统计和监控功能
6. **编写测试代码**：验证所有功能
7. **文档和总结**：编写使用说明

### 9.4 项目评估

#### 9.4.1 代码质量
- 模式使用是否正确
- 代码是否清晰可读
- 错误处理是否完善
- 并发安全性

#### 9.4.2 功能完整性
- 所有需求是否实现
- 边界情况是否处理
- 性能是否满足要求
- 内存管理是否正确

## 10. 学习总结

### 10.1 核心要点
1. **设计模式是工具**：不是所有情况都需要使用模式
2. **内核环境特殊**：必须考虑性能、并发、内存限制
3. **适度抽象**：避免过度设计影响性能
4. **组合使用**：多种模式组合解决复杂问题
5. **持续学习**：内核模式会随时间演化

### 10.2 最佳实践
1. **性能优先**：在内核中性能永远是第一位的
2. **简洁为王**：简单的解决方案往往是最好的
3. **测试充分**：内核代码的bug影响很大
4. **文档完善**：好的文档比聪明的代码更重要
5. **社区参与**：学习内核社区的编码风格

### 10.3 进阶学习
1. **阅读源代码**：在实际代码中寻找模式应用
2. **贡献代码**：通过实际项目练习模式使用
3. **性能优化**：学习如何优化模式实现
4. **架构设计**：参与大型项目的架构设计
5. **分享经验**：将学习经验分享给他人

通过这个系统的学习路径，你将能够：
- 理解设计模式的理论基础
- 掌握内核环境下的模式应用
- 提高代码设计和实现能力
- 为后续内核开发打下坚实基础

记住，设计模式是工具，而不是目标。在实际开发中，要根据具体问题选择合适的解决方案。