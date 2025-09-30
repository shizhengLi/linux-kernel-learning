# Linux内核设计模式实践示例

## 1. 实践概述

本章通过实际的代码示例，展示如何在Linux内核开发中应用各种设计模式。每个示例都包含完整的代码、构建说明和运行指导。

### 1.1 实践环境准备
```bash
# 创建内核模块开发环境
sudo apt-get install build-essential linux-headers-$(uname -r)
mkdir -p kernel-patterns-examples
cd kernel-patterns-examples
```

### 1.2 通用Makefile
```makefile
# 通用内核模块Makefile
obj-m += $(TARGET).o

KERNEL_DIR = /lib/modules/$(shell uname -r)/build

all:
    make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
    make -C $(KERNEL_DIR) M=$(PWD) clean

install:
    make -C $(KERNEL_DIR) M=$(PWD) modules_install

load:
    sudo insmod $(TARGET).ko

unload:
    sudo rmmod $(TARGET)

test:
    sudo dmesg | tail

.PHONY: all clean install load unload test
```

## 2. 单例模式实践

### 2.1 全局配置管理器

#### 2.1.1 设计目标
创建一个全局配置管理器，用于管理内核模块的配置参数。

#### 2.1.2 实现代码
```c
/* singleton-config.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>

/* 配置项结构 */
struct config_item {
    char name[32];
    int value;
    struct config_item *next;
};

/* 配置管理器单例 */
struct config_manager {
    struct mutex lock;
    struct config_item *items;
    int item_count;
    /* 单例实例指针 */
    static struct config_manager *instance;
};

/* 静态实例初始化 */
static struct config_manager *config_manager_instance = NULL;

/* 获取单例实例 */
struct config_manager *get_config_manager(void)
{
    static DEFINE_MUTEX(create_lock);

    if (config_manager_instance == NULL) {
        mutex_lock(&create_lock);
        if (config_manager_instance == NULL) {
            config_manager_instance = kzalloc(sizeof(*config_manager_instance), GFP_KERNEL);
            if (config_manager_instance) {
                mutex_init(&config_manager_instance->lock);
                config_manager_instance->items = NULL;
                config_manager_instance->item_count = 0;
                printk(KERN_INFO "ConfigManager: Singleton instance created\n");
            }
        }
        mutex_unlock(&create_lock);
    }

    return config_manager_instance;
}

/* 添加配置项 */
int config_add_item(const char *name, int value)
{
    struct config_manager *cm = get_config_manager();
    struct config_item *new_item;

    if (!cm || !name)
        return -EINVAL;

    new_item = kzalloc(sizeof(*new_item), GFP_KERNEL);
    if (!new_item)
        return -ENOMEM;

    strlcpy(new_item->name, name, sizeof(new_item->name));
    new_item->value = value;
    new_item->next = NULL;

    mutex_lock(&cm->lock);

    /* 添加到链表头部 */
    new_item->next = cm->items;
    cm->items = new_item;
    cm->item_count++;

    mutex_unlock(&cm->lock);

    printk(KERN_INFO "ConfigManager: Added item %s = %d\n", name, value);
    return 0;
}

/* 获取配置项 */
int config_get_item(const char *name, int *value)
{
    struct config_manager *cm = get_config_manager();
    struct config_item *item;

    if (!cm || !name || !value)
        return -EINVAL;

    mutex_lock(&cm->lock);

    item = cm->items;
    while (item) {
        if (strcmp(item->name, name) == 0) {
            *value = item->value;
            mutex_unlock(&cm->lock);
            return 0;
        }
        item = item->next;
    }

    mutex_unlock(&cm->lock);
    return -ENOENT;
}

/* 更新配置项 */
int config_update_item(const char *name, int new_value)
{
    struct config_manager *cm = get_config_manager();
    struct config_item *item;

    if (!cm || !name)
        return -EINVAL;

    mutex_lock(&cm->lock);

    item = cm->items;
    while (item) {
        if (strcmp(item->name, name) == 0) {
            item->value = new_value;
            mutex_unlock(&cm->lock);
            printk(KERN_INFO "ConfigManager: Updated %s = %d\n", name, new_value);
            return 0;
        }
        item = item->next;
    }

    mutex_unlock(&cm->lock);
    return -ENOENT;
}

/* 模块初始化 */
static int __init singleton_config_init(void)
{
    struct config_manager *cm;

    printk(KERN_INFO "SingletonConfig: Module loaded\n");

    cm = get_config_manager();
    if (!cm) {
        printk(KERN_ERR "SingletonConfig: Failed to get config manager\n");
        return -ENOMEM;
    }

    /* 添加一些默认配置 */
    config_add_item("log_level", 3);
    config_add_item("buffer_size", 1024);
    config_add_item("timeout", 30);

    return 0;
}

/* 模块退出 */
static void __exit singleton_config_exit(void)
{
    struct config_manager *cm = get_config_manager();
    struct config_item *item, *tmp;

    if (cm) {
        mutex_lock(&cm->lock);

        /* 释放所有配置项 */
        item = cm->items;
        while (item) {
            tmp = item;
            item = item->next;
            kfree(tmp);
        }

        mutex_unlock(&cm->lock);
        kfree(cm);
        config_manager_instance = NULL;

        printk(KERN_INFO "SingletonConfig: Config manager destroyed\n");
    }

    printk(KERN_INFO "SingletonConfig: Module unloaded\n");
}

/* 导出函数供其他模块使用 */
EXPORT_SYMBOL(get_config_manager);
EXPORT_SYMBOL(config_add_item);
EXPORT_SYMBOL(config_get_item);
EXPORT_SYMBOL(config_update_item);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel singleton pattern example");
module_init(singleton_config_init);
module_exit(singleton_config_exit);
```

#### 2.1.3 测试代码
```c
/* singleton-test.c */
#include <linux/module.h>
#include <linux/kernel.h>

/* 声明外部函数 */
extern struct config_manager *get_config_manager(void);
extern int config_get_item(const char *name, int *value);
extern int config_update_item(const char *name, int new_value);

static int __init singleton_test_init(void)
{
    struct config_manager *cm;
    int value, ret;

    printk(KERN_INFO "SingletonTest: Module loaded\n");

    /* 获取配置管理器实例 */
    cm = get_config_manager();
    if (!cm) {
        printk(KERN_ERR "SingletonTest: Failed to get config manager\n");
        return -ENODEV;
    }

    /* 测试配置项读取 */
    ret = config_get_item("log_level", &value);
    if (ret == 0) {
        printk(KERN_INFO "SingletonTest: log_level = %d\n", value);
    }

    ret = config_get_item("buffer_size", &value);
    if (ret == 0) {
        printk(KERN_INFO "SingletonTest: buffer_size = %d\n", value);
    }

    /* 更新配置项 */
    config_update_item("log_level", 5);

    /* 再次读取验证更新 */
    ret = config_get_item("log_level", &value);
    if (ret == 0) {
        printk(KERN_INFO "SingletonTest: Updated log_level = %d\n", value);
    }

    return 0;
}

static void __exit singleton_test_exit(void)
{
    printk(KERN_INFO "SingletonTest: Module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Singleton pattern test module");
module_init(singleton_test_init);
module_exit(singleton_test_exit);
```

#### 2.1.4 构建和运行
```bash
# 编译
make TARGET=singleton-config
make TARGET=singleton-test

# 加载模块
sudo insmod singleton-config.ko
sudo insmod singleton-test.ko

# 查看日志
dmesg | tail -10

# 卸载模块
sudo rmmod singleton-test
sudo rmmod singleton-config
```

## 3. 工厂模式实践

### 3.1 设备类型工厂

#### 3.1.1 设计目标
创建一个设备类型工厂，能够根据不同的设备类型创建相应的设备对象。

#### 3.1.2 实现代码
```c
/* factory-devices.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/fs.h>

/* 设备类型枚举 */
enum device_type {
    DEVICE_TYPE_SENSOR,
    DEVICE_TYPE_ACTUATOR,
    DEVICE_TYPE_CONTROLLER,
    DEVICE_TYPE_UNKNOWN
};

/* 抽象设备结构 */
struct abstract_device {
    enum device_type type;
    char name[32];
    int id;

    /* 设备操作接口 */
    int (*init)(struct abstract_device *dev);
    int (*start)(struct abstract_device *dev);
    int (*stop)(struct abstract_device *dev);
    void (*cleanup)(struct abstract_device *dev);

    /* 私有数据 */
    void *private_data;
};

/* 具体设备结构 */
struct sensor_device {
    struct abstract_device base;
    int sensitivity;
    int sampling_rate;
};

struct actuator_device {
    struct abstract_device base;
    int max_force;
    int precision;
};

struct controller_device {
    struct abstract_device base;
    int num_inputs;
    int num_outputs;
};

/* 工厂接口 */
struct device_factory {
    struct abstract_device* (*create_device)(enum device_type type, int id);
    void (*destroy_device)(struct abstract_device *device);
};

/* 前向声明 */
static int sensor_init(struct abstract_device *dev);
static int sensor_start(struct abstract_device *dev);
static int sensor_stop(struct abstract_device *dev);
static void sensor_cleanup(struct abstract_device *dev);

static int actuator_init(struct abstract_device *dev);
static int actuator_start(struct abstract_device *dev);
static int actuator_stop(struct abstract_device *dev);
static void actuator_cleanup(struct abstract_device *dev);

static int controller_init(struct abstract_device *dev);
static int controller_start(struct abstract_device *dev);
static int controller_stop(struct abstract_device *dev);
static void controller_cleanup(struct abstract_device *dev);

/* 工厂创建函数 */
static struct abstract_device* factory_create_device(enum device_type type, int id)
{
    struct abstract_device *device = NULL;

    switch (type) {
    case DEVICE_TYPE_SENSOR: {
        struct sensor_device *sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
        if (sensor) {
            sensor->base.type = DEVICE_TYPE_SENSOR;
            sprintf(sensor->base.name, "sensor_%d", id);
            sensor->base.id = id;
            sensor->base.init = sensor_init;
            sensor->base.start = sensor_start;
            sensor->base.stop = sensor_stop;
            sensor->base.cleanup = sensor_cleanup;
            sensor->base.private_data = sensor;
            sensor->sensitivity = 100;
            sensor->sampling_rate = 1000;
            device = &sensor->base;
        }
        break;
    }

    case DEVICE_TYPE_ACTUATOR: {
        struct actuator_device *actuator = kzalloc(sizeof(*actuator), GFP_KERNEL);
        if (actuator) {
            actuator->base.type = DEVICE_TYPE_ACTUATOR;
            sprintf(actuator->base.name, "actuator_%d", id);
            actuator->base.id = id;
            actuator->base.init = actuator_init;
            actuator->base.start = actuator_start;
            actuator->base.stop = actuator_stop;
            actuator->base.cleanup = actuator_cleanup;
            actuator->base.private_data = actuator;
            actuator->max_force = 500;
            actuator->precision = 10;
            device = &actuator->base;
        }
        break;
    }

    case DEVICE_TYPE_CONTROLLER: {
        struct controller_device *controller = kzalloc(sizeof(*controller), GFP_KERNEL);
        if (controller) {
            controller->base.type = DEVICE_TYPE_CONTROLLER;
            sprintf(controller->base.name, "controller_%d", id);
            controller->base.id = id;
            controller->base.init = controller_init;
            controller->base.start = controller_start;
            controller->base.stop = controller_stop;
            controller->base.cleanup = controller_cleanup;
            controller->base.private_data = controller;
            controller->num_inputs = 8;
            controller->num_outputs = 4;
            device = &controller->base;
        }
        break;
    }

    default:
        printk(KERN_ERR "DeviceFactory: Unknown device type %d\n", type);
        break;
    }

    if (device) {
        printk(KERN_INFO "DeviceFactory: Created %s device '%s' (id=%d)\n",
               device->type == DEVICE_TYPE_SENSOR ? "sensor" :
               device->type == DEVICE_TYPE_ACTUATOR ? "actuator" : "controller",
               device->name, device->id);
    }

    return device;
}

static void factory_destroy_device(struct abstract_device *device)
{
    if (!device)
        return;

    printk(KERN_INFO "DeviceFactory: Destroying device '%s'\n", device->name);

    if (device->cleanup)
        device->cleanup(device);

    kfree(device->private_data);
}

/* 传感器设备实现 */
static int sensor_init(struct abstract_device *dev)
{
    struct sensor_device *sensor = container_of(dev, struct sensor_device, base);
    printk(KERN_INFO "Sensor: Initializing sensor device '%s' (sensitivity=%d, rate=%d)\n",
           dev->name, sensor->sensitivity, sensor->sampling_rate);
    return 0;
}

static int sensor_start(struct abstract_device *dev)
{
    printk(KERN_INFO "Sensor: Starting sensor device '%s'\n", dev->name);
    return 0;
}

static int sensor_stop(struct abstract_device *dev)
{
    printk(KERN_INFO "Sensor: Stopping sensor device '%s'\n", dev->name);
    return 0;
}

static void sensor_cleanup(struct abstract_device *dev)
{
    printk(KERN_INFO "Sensor: Cleaning up sensor device '%s'\n", dev->name);
}

/* 执行器设备实现 */
static int actuator_init(struct abstract_device *dev)
{
    struct actuator_device *actuator = container_of(dev, struct actuator_device, base);
    printk(KERN_INFO "Actuator: Initializing actuator device '%s' (max_force=%d, precision=%d)\n",
           dev->name, actuator->max_force, actuator->precision);
    return 0;
}

static int actuator_start(struct abstract_device *dev)
{
    printk(KERN_INFO "Actuator: Starting actuator device '%s'\n", dev->name);
    return 0;
}

static int actuator_stop(struct abstract_device *dev)
{
    printk(KERN_INFO "Actuator: Stopping actuator device '%s'\n", dev->name);
    return 0;
}

static void actuator_cleanup(struct abstract_device *dev)
{
    printk(KERN_INFO "Actuator: Cleaning up actuator device '%s'\n", dev->name);
}

/* 控制器设备实现 */
static int controller_init(struct abstract_device *dev)
{
    struct controller_device *controller = container_of(dev, struct controller_device, base);
    printk(KERN_INFO "Controller: Initializing controller device '%s' (inputs=%d, outputs=%d)\n",
           dev->name, controller->num_inputs, controller->num_outputs);
    return 0;
}

static int controller_start(struct abstract_device *dev)
{
    printk(KERN_INFO "Controller: Starting controller device '%s'\n", dev->name);
    return 0;
}

static int controller_stop(struct abstract_device *dev)
{
    printk(KERN_INFO "Controller: Stopping controller device '%s'\n", dev->name);
    return 0;
}

static void controller_cleanup(struct abstract_device *dev)
{
    printk(KERN_INFO "Controller: Cleaning up controller device '%s'\n", dev->name);
}

/* 工厂实例 */
static struct device_factory device_factory = {
    .create_device = factory_create_device,
    .destroy_device = factory_destroy_device,
};

/* 模块初始化 - 演示工厂模式 */
static int __init factory_devices_init(void)
{
    struct abstract_device *devices[3];
    int i;

    printk(KERN_INFO "FactoryDevices: Module loaded\n");

    /* 使用工厂创建不同类型的设备 */
    devices[0] = device_factory.create_device(DEVICE_TYPE_SENSOR, 1);
    devices[1] = device_factory.create_device(DEVICE_TYPE_ACTUATOR, 1);
    devices[2] = device_factory.create_device(DEVICE_TYPE_CONTROLLER, 1);

    /* 初始化和启动设备 */
    for (i = 0; i < 3; i++) {
        if (devices[i]) {
            if (devices[i]->init(devices[i]) == 0) {
                devices[i]->start(devices[i]);
            }
        }
    }

    /* 停止和清理设备 */
    for (i = 0; i < 3; i++) {
        if (devices[i]) {
            devices[i]->stop(devices[i]);
            device_factory.destroy_device(devices[i]);
        }
    }

    return 0;
}

static void __exit factory_devices_exit(void)
{
    printk(KERN_INFO "FactoryDevices: Module unloaded\n");
}

/* 导出工厂接口 */
EXPORT_SYMBOL(device_factory);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel factory pattern example");
module_init(factory_devices_init);
module_exit(factory_devices_exit);
```

#### 3.1.3 测试代码
```c
/* factory-test.c */
#include <linux/module.h>
#include <linux/kernel.h>

/* 声明外部工厂接口 */
extern struct device_factory {
    struct abstract_device* (*create_device)(enum device_type type, int id);
    void (*destroy_device)(struct abstract_device *device);
} device_factory;

static int __init factory_test_init(void)
{
    struct abstract_device *device;

    printk(KERN_INFO "FactoryTest: Module loaded\n");

    /* 测试创建传感器 */
    device = device_factory.create_device(DEVICE_TYPE_SENSOR, 100);
    if (device) {
        device->init(device);
        device->start(device);
        device->stop(device);
        device_factory.destroy_device(device);
    }

    /* 测试创建执行器 */
    device = device_factory.create_device(DEVICE_TYPE_ACTUATOR, 200);
    if (device) {
        device->init(device);
        device->start(device);
        device->stop(device);
        device_factory.destroy_device(device);
    }

    return 0;
}

static void __exit factory_test_exit(void)
{
    printk(KERN_INFO "FactoryTest: Module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Factory pattern test module");
module_init(factory_test_init);
module_exit(factory_test_exit);
```

## 4. 观察者模式实践

### 4.1 事件通知系统

#### 4.1.1 设计目标
实现一个事件通知系统，允许模块注册和接收系统事件的通知。

#### 4.1.2 实现代码
```c
/* observer-notifier.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <linux/list.h>

/* 事件类型定义 */
enum system_event {
    EVENT_SYSTEM_BOOT,
    EVENT_SYSTEM_SHUTDOWN,
    EVENT_DEVICE_ADDED,
    EVENT_DEVICE_REMOVED,
    EVENT_ERROR_OCCURRED,
    EVENT_MAX
};

/* 事件数据结构 */
struct event_data {
    enum system_event event_type;
    int event_id;
    char description[128];
    void *data;
    size_t data_size;
};

/* 观察者接口 */
struct event_observer {
    struct list_head list;
    int (*notify)(struct event_observer *observer, struct event_data *event);
    void *private_data;
    const char *name;
};

/* 事件通知器 */
struct event_notifier {
    struct list_head observers;
    spinlock_t lock;
    int next_event_id;
};

/* 全局通知器实例 */
static struct event_notifier system_notifier;

/* 初始化通知器 */
static void notifier_init(struct event_notifier *notifier)
{
    INIT_LIST_HEAD(&notifier->observers);
    spin_lock_init(&notifier->lock);
    notifier->next_event_id = 1;
}

/* 注册观察者 */
int notifier_register_observer(struct event_observer *observer)
{
    unsigned long flags;

    if (!observer || !observer->notify)
        return -EINVAL;

    spin_lock_irqsave(&system_notifier.lock, flags);
    list_add_tail(&observer->list, &system_notifier.observers);
    spin_unlock_irqrestore(&system_notifier.lock, flags);

    printk(KERN_INFO "EventNotifier: Observer '%s' registered\n", observer->name);
    return 0;
}

/* 注销观察者 */
void notifier_unregister_observer(struct event_observer *observer)
{
    unsigned long flags;

    if (!observer)
        return;

    spin_lock_irqsave(&system_notifier.lock, flags);
    list_del(&observer->list);
    spin_unlock_irqrestore(&system_notifier.lock, flags);

    printk(KERN_INFO "EventNotifier: Observer '%s' unregistered\n", observer->name);
}

/* 发送事件通知 */
int notifier_send_event(enum system_event event_type, const char *description,
                       void *data, size_t data_size)
{
    struct event_data event;
    struct event_observer *observer;
    unsigned long flags;
    int notified_count = 0;

    /* 准备事件数据 */
    event.event_type = event_type;
    event.event_id = system_notifier.next_event_id++;
    event.data = data;
    event.data_size = data_size;

    if (description)
        strlcpy(event.description, description, sizeof(event.description));
    else
        event.description[0] = '\0';

    printk(KERN_INFO "EventNotifier: Sending event %d (type=%d, desc='%s')\n",
           event.event_id, event.event_type, event.description);

    /* 通知所有观察者 */
    spin_lock_irqsave(&system_notifier.lock, flags);
    list_for_each_entry(observer, &system_notifier.observers, list) {
        if (observer->notify(observer, &event) == 0) {
            notified_count++;
        }
    }
    spin_unlock_irqrestore(&system_notifier.lock, flags);

    printk(KERN_INFO "EventNotifier: Event %d notified to %d observers\n",
           event.event_id, notified_count);

    return event.event_id;
}

/* 示例观察者1：日志记录器 */
static int logger_observer_notify(struct event_observer *observer,
                                 struct event_data *event)
{
    printk(KERN_INFO "LoggerObserver: [%s] Event %d: %s\n",
           observer->name, event->event_id, event->description);
    return 0;
}

static struct event_observer logger_observer = {
    .notify = logger_observer_notify,
    .name = "SystemLogger",
};

/* 示例观察者2：错误处理器 */
static int error_observer_notify(struct event_observer *observer,
                                struct event_data *event)
{
    if (event->event_type == EVENT_ERROR_OCCURRED) {
        printk(KERN_ERR "ErrorObserver: CRITICAL ERROR - %s\n", event->description);
        /* 这里可以添加错误处理逻辑 */
    }
    return 0;
}

static struct event_observer error_observer = {
    .notify = error_observer_notify,
    .name = "ErrorHandler",
};

/* 示例观察者3：设备管理器 */
static int device_observer_notify(struct event_observer *observer,
                                 struct event_data *event)
{
    if (event->event_type == EVENT_DEVICE_ADDED) {
        printk(KERN_INFO "DeviceObserver: New device detected - %s\n",
               event->description);
    } else if (event->event_type == EVENT_DEVICE_REMOVED) {
        printk(KERN_INFO "DeviceObserver: Device removed - %s\n",
               event->description);
    }
    return 0;
}

static struct event_observer device_observer = {
    .notify = device_observer_notify,
    .name = "DeviceManager",
};

/* 模块初始化 */
static int __init observer_notifier_init(void)
{
    printk(KERN_INFO "ObserverNotifier: Module loaded\n");

    /* 初始化通知器 */
    notifier_init(&system_notifier);

    /* 注册观察者 */
    notifier_register_observer(&logger_observer);
    notifier_register_observer(&error_observer);
    notifier_register_observer(&device_observer);

    /* 发送一些测试事件 */
    notifier_send_event(EVENT_SYSTEM_BOOT, "System boot completed", NULL, 0);
    notifier_send_event(EVENT_DEVICE_ADDED, "USB device detected", NULL, 0);
    notifier_send_event(EVENT_ERROR_OCCURRED, "Memory allocation failed", NULL, 0);
    notifier_send_event(EVENT_DEVICE_REMOVED, "USB device disconnected", NULL, 0);

    return 0;
}

/* 模块退出 */
static void __exit observer_notifier_exit(void)
{
    /* 注销观察者 */
    notifier_unregister_observer(&logger_observer);
    notifier_unregister_observer(&error_observer);
    notifier_unregister_observer(&device_observer);

    /* 发送关闭事件 */
    notifier_send_event(EVENT_SYSTEM_SHUTDOWN, "System shutting down", NULL, 0);

    printk(KERN_INFO "ObserverNotifier: Module unloaded\n");
}

/* 导出接口 */
EXPORT_SYMBOL(notifier_register_observer);
EXPORT_SYMBOL(notifier_unregister_observer);
EXPORT_SYMBOL(notifier_send_event);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel observer pattern example");
module_init(observer_notifier_init);
module_exit(observer_notifier_exit);
```

## 5. 策略模式实践

### 5.1 内存分配策略

#### 5.1.1 设计目标
实现一个支持多种内存分配策略的内存管理器，可以根据需要切换不同的分配策略。

#### 5.1.2 实现代码
```c
/* strategy-memory.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/gfp.h>

/* 分配策略类型 */
enum allocation_strategy {
    STRATEGY_KMALLOC,      /* 使用kmalloc */
    STRATEGY_VMALLOC,      /* 使用vmalloc */
    STRATEGY_KZALLOC,      /* 使用kzalloc */
    STRATEGY_GFP_ATOMIC    /* 使用GFP_ATOMIC */
};

/* 策略接口 */
struct allocation_policy {
    void* (*alloc)(size_t size, gfp_t flags);
    void (*free)(void *ptr);
    const char *name;
};

/* 策略实例 */
static void* kmalloc_policy_alloc(size_t size, gfp_t flags)
{
    return kmalloc(size, flags);
}

static void kmalloc_policy_free(void *ptr)
{
    kfree(ptr);
}

static struct allocation_policy kmalloc_policy = {
    .alloc = kmalloc_policy_alloc,
    .free = kmalloc_policy_free,
    .name = "kmalloc"
};

static void* vmalloc_policy_alloc(size_t size, gfp_t flags)
{
    (void)flags; /* vmalloc不使用flags */
    return vmalloc(size);
}

static void vmalloc_policy_free(void *ptr)
{
    vfree(ptr);
}

static struct allocation_policy vmalloc_policy = {
    .alloc = vmalloc_policy_alloc,
    .free = vmalloc_policy_free,
    .name = "vmalloc"
};

static void* kzalloc_policy_alloc(size_t size, gfp_t flags)
{
    return kzalloc(size, flags);
}

static void kzalloc_policy_free(void *ptr)
{
    kfree(ptr);
}

static struct allocation_policy kzalloc_policy = {
    .alloc = kzalloc_policy_alloc,
    .free = kzalloc_policy_free,
    .name = "kzalloc"
};

static void* gfp_atomic_policy_alloc(size_t size, gfp_t flags)
{
    return kmalloc(size, flags | GFP_ATOMIC);
}

static void gfp_atomic_policy_free(void *ptr)
{
    kfree(ptr);
}

static struct allocation_policy gfp_atomic_policy = {
    .alloc = gfp_atomic_policy_alloc,
    .free = gfp_atomic_policy_free,
    .name = "gfp_atomic"
};

/* 策略管理器 */
struct strategy_manager {
    struct allocation_policy *current_policy;
    struct allocation_policy *policies[4];
    int num_policies;
};

static struct strategy_manager memory_manager;

/* 初始化策略管理器 */
static void strategy_manager_init(struct strategy_manager *manager)
{
    manager->policies[0] = &kmalloc_policy;
    manager->policies[1] = &vmalloc_policy;
    manager->policies[2] = &kzalloc_policy;
    manager->policies[3] = &gfp_atomic_policy;
    manager->num_policies = 4;
    manager->current_policy = &kmalloc_policy; /* 默认策略 */
}

/* 切换策略 */
int strategy_manager_set_strategy(struct strategy_manager *manager,
                                enum allocation_strategy strategy)
{
    if (strategy < 0 || strategy >= manager->num_policies)
        return -EINVAL;

    manager->current_policy = manager->policies[strategy];
    printk(KERN_INFO "StrategyManager: Switched to %s strategy\n",
           manager->current_policy->name);
    return 0;
}

/* 获取当前策略名称 */
const char* strategy_manager_get_current_strategy(struct strategy_manager *manager)
{
    return manager->current_policy ? manager->current_policy->name : "none";
}

/* 使用当前策略分配内存 */
void* strategy_manager_alloc(struct strategy_manager *manager,
                            size_t size, gfp_t flags)
{
    if (!manager->current_policy)
        return NULL;

    return manager->current_policy->alloc(size, flags);
}

/* 使用当前策略释放内存 */
void strategy_manager_free(struct strategy_manager *manager, void *ptr)
{
    if (!manager->current_policy || !ptr)
        return;

    manager->current_policy->free(ptr);
}

/* 内存分配统计 */
struct allocation_stats {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    unsigned long allocation_count;
    unsigned long free_count;
};

static struct allocation_stats mem_stats;

/* 带统计的包装函数 */
void* stats_alloc(struct strategy_manager *manager, size_t size, gfp_t flags)
{
    void *ptr = strategy_manager_alloc(manager, size, flags);

    if (ptr) {
        unsigned long irq_flags;
        local_irq_save(irq_flags);
        mem_stats.total_allocated += size;
        mem_stats.current_usage += size;
        mem_stats.allocation_count++;
        local_irq_restore(irq_flags);
    }

    return ptr;
}

void stats_free(struct strategy_manager *manager, void *ptr, size_t size)
{
    if (ptr) {
        unsigned long irq_flags;
        local_irq_save(irq_flags);
        mem_stats.total_freed += size;
        mem_stats.current_usage -= size;
        mem_stats.free_count++;
        local_irq_restore(irq_flags);
    }

    strategy_manager_free(manager, ptr);
}

/* 打印统计信息 */
void strategy_manager_print_stats(struct strategy_manager *manager)
{
    printk(KERN_INFO "StrategyManager Statistics:\n");
    printk(KERN_INFO "  Current strategy: %s\n",
           strategy_manager_get_current_strategy(manager));
    printk(KERN_INFO "  Total allocated: %zu bytes\n", mem_stats.total_allocated);
    printk(KERN_INFO "  Total freed: %zu bytes\n", mem_stats.total_freed);
    printk(KERN_INFO "  Current usage: %zu bytes\n", mem_stats.current_usage);
    printk(KERN_INFO "  Allocations: %lu\n", mem_stats.allocation_count);
    printk(KERN_INFO "  Frees: %lu\n", mem_stats.free_count);
}

/* 模块初始化 */
static int __init strategy_memory_init(void)
{
    void *ptr1, *ptr2, *ptr3, *ptr4;

    printk(KERN_INFO "StrategyMemory: Module loaded\n");

    /* 初始化策略管理器 */
    strategy_manager_init(&memory_manager);

    /* 测试不同策略 */
    printk(KERN_INFO "StrategyMemory: Testing different allocation strategies\n");

    /* 策略1：kmalloc */
    strategy_manager_set_strategy(&memory_manager, STRATEGY_KMALLOC);
    ptr1 = stats_alloc(&memory_manager, 1024, GFP_KERNEL);
    printk(KERN_INFO "StrategyMemory: Allocated 1024 bytes with %s\n",
           strategy_manager_get_current_strategy(&memory_manager));

    /* 策略2：vmalloc */
    strategy_manager_set_strategy(&memory_manager, STRATEGY_VMALLOC);
    ptr2 = stats_alloc(&memory_manager, 2048, GFP_KERNEL);
    printk(KERN_INFO "StrategyMemory: Allocated 2048 bytes with %s\n",
           strategy_manager_get_current_strategy(&memory_manager));

    /* 策略3：kzalloc */
    strategy_manager_set_strategy(&memory_manager, STRATEGY_KZALLOC);
    ptr3 = stats_alloc(&memory_manager, 512, GFP_KERNEL);
    printk(KERN_INFO "StrategyMemory: Allocated 512 bytes with %s\n",
           strategy_manager_get_current_strategy(&memory_manager));

    /* 策略4：gfp_atomic */
    strategy_manager_set_strategy(&memory_manager, STRATEGY_GFP_ATOMIC);
    ptr4 = stats_alloc(&memory_manager, 256, GFP_KERNEL);
    printk(KERN_INFO "StrategyMemory: Allocated 256 bytes with %s\n",
           strategy_manager_get_current_strategy(&memory_manager));

    /* 打印统计信息 */
    strategy_manager_print_stats(&memory_manager);

    /* 释放内存 */
    stats_free(&memory_manager, ptr1, 1024);
    stats_free(&memory_manager, ptr2, 2048);
    stats_free(&memory_manager, ptr3, 512);
    stats_free(&memory_manager, ptr4, 256);

    /* 最终统计 */
    printk(KERN_INFO "StrategyMemory: Final statistics after cleanup:\n");
    strategy_manager_print_stats(&memory_manager);

    return 0;
}

/* 模块退出 */
static void __exit strategy_memory_exit(void)
{
    printk(KERN_INFO "StrategyMemory: Module unloaded\n");
}

/* 导出接口 */
EXPORT_SYMBOL(strategy_manager_set_strategy);
EXPORT_SYMBOL(strategy_manager_get_current_strategy);
EXPORT_SYMBOL(strategy_manager_alloc);
EXPORT_SYMBOL(strategy_manager_free);
EXPORT_SYMBOL(stats_alloc);
EXPORT_SYMBOL(stats_free);
EXPORT_SYMBOL(strategy_manager_print_stats);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel strategy pattern example");
module_init(strategy_memory_init);
module_exit(strategy_memory_exit);
```

## 6. 命令模式实践

### 6.1 任务队列系统

#### 6.1.1 设计目标
实现一个基于命令模式的任务队列系统，支持异步任务执行和撤销操作。

#### 6.1.2 实现代码
```c
/* command-queue.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

/* 命令接口 */
struct command {
    struct list_head list;

    /* 命令操作 */
    int (*execute)(struct command *cmd);
    int (*undo)(struct command *cmd);
    void (*cleanup)(struct command *cmd);

    /* 命令属性 */
    const char *name;
    int id;
    bool executed;
    bool undone;

    /* 命令数据 */
    void *data;
};

/* 命令队列 */
struct command_queue {
    struct list_head pending_commands;
    struct list_head executed_commands;
    struct workqueue_struct *workqueue;
    struct work_struct work;
    spinlock_t lock;
    struct mutex mutex;
    int next_command_id;
    atomic_t active_commands;
};

/* 示例命令1：打印消息 */
struct print_command {
    struct command base;
    char message[256];
    int priority;
};

static int print_command_execute(struct command *cmd)
{
    struct print_command *print_cmd = container_of(cmd, struct print_command, base);

    printk(KERN_INFO "PrintCommand[%d]: %s (priority=%d)\n",
           cmd->id, print_cmd->message, print_cmd->priority);

    cmd->executed = true;
    return 0;
}

static int print_command_undo(struct command *cmd)
{
    struct print_command *print_cmd = container_of(cmd, struct print_command, base);

    printk(KERN_INFO "PrintCommand[%d]: Undone - %s\n",
           cmd->id, print_cmd->message);

    cmd->undone = true;
    return 0;
}

static void print_command_cleanup(struct command *cmd)
{
    struct print_command *print_cmd = container_of(cmd, struct print_command, base);
    printk(KERN_INFO "PrintCommand[%d]: Cleanup\n", cmd->id);
    kfree(print_cmd);
}

static struct command* create_print_command(const char *message, int priority)
{
    struct print_command *cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);

    if (!cmd)
        return NULL;

    strlcpy(cmd->message, message, sizeof(cmd->message));
    cmd->priority = priority;

    cmd->base.execute = print_command_execute;
    cmd->base.undo = print_command_undo;
    cmd->base.cleanup = print_command_cleanup;
    cmd->base.name = "print";

    return &cmd->base;
}

/* 示例命令2：延迟操作 */
struct delay_command {
    struct command base;
    unsigned long delay_ms;
    struct timer_list timer;
    struct command_queue *queue;
    struct delayed_work dwork;
};

static void delay_command_work(struct work_struct *work)
{
    struct delay_command *delay_cmd = container_of(work, struct delay_command, dwork.work);

    printk(KERN_INFO "DelayCommand[%d]: Delayed operation completed (%lu ms)\n",
           delay_cmd->base.id, delay_cmd->delay_ms);

    delay_cmd->base.executed = true;
    atomic_dec(&delay_cmd->queue->active_commands);
}

static int delay_command_execute(struct command *cmd)
{
    struct delay_command *delay_cmd = container_of(cmd, struct delay_command, base);

    printk(KERN_INFO "DelayCommand[%d]: Starting delayed operation (%lu ms)\n",
           cmd->id, delay_cmd->delay_ms);

    INIT_DELAYED_WORK(&delay_cmd->dwork, delay_command_work);
    schedule_delayed_work(&delay_cmd->dwork, msecs_to_jiffies(delay_cmd->delay_ms));

    atomic_inc(&delay_cmd->queue->active_commands);
    /* 延迟命令标记为已执行，但实际完成在工作函数中 */
    return 0;
}

static int delay_command_undo(struct command *cmd)
{
    struct delay_command *delay_cmd = container_of(cmd, struct delay_command, base);

    cancel_delayed_work_sync(&delay_cmd->dwork);

    printk(KERN_INFO "DelayCommand[%d]: Cancelled delayed operation\n", cmd->id);

    cmd->undone = true;
    atomic_dec(&delay_cmd->queue->active_commands);

    return 0;
}

static void delay_command_cleanup(struct command *cmd)
{
    struct delay_command *delay_cmd = container_of(cmd, struct delay_command, base);
    printk(KERN_INFO "DelayCommand[%d]: Cleanup\n", cmd->id);
    kfree(delay_cmd);
}

static struct command* create_delay_command(unsigned long delay_ms, struct command_queue *queue)
{
    struct delay_command *cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);

    if (!cmd)
        return NULL;

    cmd->delay_ms = delay_ms;
    cmd->queue = queue;

    cmd->base.execute = delay_command_execute;
    cmd->base.undo = delay_command_undo;
    cmd->base.cleanup = delay_command_cleanup;
    cmd->base.name = "delay";

    return &cmd->base;
}

/* 全局命令队列 */
static struct command_queue global_queue;

/* 初始化命令队列 */
static void command_queue_init(struct command_queue *queue)
{
    INIT_LIST_HEAD(&queue->pending_commands);
    INIT_LIST_HEAD(&queue->executed_commands);
    queue->workqueue = create_singlethread_workqueue("command_queue");
    INIT_WORK(&queue->work, command_queue_process);
    spin_lock_init(&queue->lock);
    mutex_init(&queue->mutex);
    queue->next_command_id = 1;
    atomic_set(&queue->active_commands, 0);
}

/* 队列处理工作函数 */
static void command_queue_process(struct work_struct *work)
{
    struct command_queue *queue = container_of(work, struct command_queue, work);
    struct command *cmd, *tmp;
    LIST_HEAD(process_list);

    spin_lock(&queue->lock);
    list_splice_init(&queue->pending_commands, &process_list);
    spin_unlock(&queue->lock);

    list_for_each_entry_safe(cmd, tmp, &process_list, list) {
        list_del(&cmd->list);

        if (cmd->execute(cmd) == 0) {
            /* 成功执行，移到已执行列表 */
            spin_lock(&queue->lock);
            list_add_tail(&cmd->list, &queue->executed_commands);
            spin_unlock(&queue->lock);
        } else {
            /* 执行失败，清理 */
            cmd->cleanup(cmd);
        }
    }
}

/* 添加命令到队列 */
int command_queue_add(struct command_queue *queue, struct command *cmd)
{
    if (!queue || !cmd)
        return -EINVAL;

    cmd->id = queue->next_command_id++;

    spin_lock(&queue->lock);
    list_add_tail(&cmd->list, &queue->pending_commands);
    spin_unlock(&queue->lock);

    printk(KERN_INFO "CommandQueue: Added command %d (%s)\n", cmd->id, cmd->name);

    /* 触发队列处理 */
    queue_work(queue->workqueue, &queue->work);

    return cmd->id;
}

/* 撤销最后的命令 */
int command_queue_undo_last(struct command_queue *queue)
{
    struct command *cmd = NULL;
    int ret = -ENOENT;

    if (!queue)
        return -EINVAL;

    mutex_lock(&queue->mutex);

    spin_lock(&queue->lock);
    if (!list_empty(&queue->executed_commands)) {
        cmd = list_last_entry(&queue->executed_commands, struct command, list);
        list_del(&cmd->list);
    }
    spin_unlock(&queue->lock);

    if (cmd) {
        ret = cmd->undo(cmd);
        if (ret == 0) {
            printk(KERN_INFO "CommandQueue: Undone command %d (%s)\n",
                   cmd->id, cmd->name);
        } else {
            /* 撤销失败，重新添加到已执行列表 */
            spin_lock(&queue->lock);
            list_add_tail(&cmd->list, &queue->executed_commands);
            spin_unlock(&queue->lock);
        }
    }

    mutex_unlock(&queue->mutex);

    return ret;
}

/* 清理命令队列 */
void command_queue_cleanup(struct command_queue *queue)
{
    struct command *cmd, *tmp;

    if (!queue)
        return;

    /* 取消未执行命令 */
    spin_lock(&queue->lock);
    list_for_each_entry_safe(cmd, tmp, &queue->pending_commands, list) {
        list_del(&cmd->list);
        cmd->cleanup(cmd);
    }

    /* 清理已执行命令 */
    list_for_each_entry_safe(cmd, tmp, &queue->executed_commands, list) {
        list_del(&cmd->list);
        cmd->cleanup(cmd);
    }
    spin_unlock(&queue->lock);

    /* 等待所有活动命令完成 */
    while (atomic_read(&queue->active_commands) > 0) {
        msleep(100);
    }

    /* 销毁工作队列 */
    if (queue->workqueue) {
        flush_workqueue(queue->workqueue);
        destroy_workqueue(queue->workqueue);
    }

    printk(KERN_INFO "CommandQueue: Queue cleaned up\n");
}

/* 模块初始化 */
static int __init command_queue_init_module(void)
{
    struct command *cmd1, *cmd2, *cmd3, *cmd4;

    printk(KERN_INFO "CommandQueue: Module loaded\n");

    /* 初始化全局队列 */
    command_queue_init(&global_queue);

    /* 创建和添加命令 */
    cmd1 = create_print_command("Hello from command 1", 1);
    cmd2 = create_print_command("Hello from command 2", 2);
    cmd3 = create_print_command("Hello from command 3", 3);
    cmd4 = create_delay_command(2000, &global_queue); /* 2秒延迟 */

    if (cmd1) command_queue_add(&global_queue, cmd1);
    if (cmd2) command_queue_add(&global_queue, cmd2);
    if (cmd3) command_queue_add(&global_queue, cmd3);
    if (cmd4) command_queue_add(&global_queue, cmd4);

    /* 等待一些命令完成 */
    msleep(100);

    /* 尝试撤销最后的命令 */
    command_queue_undo_last(&global_queue);

    /* 等待所有命令完成 */
    msleep(3000);

    return 0;
}

/* 模块退出 */
static void __exit command_queue_exit_module(void)
{
    command_queue_cleanup(&global_queue);
    printk(KERN_INFO "CommandQueue: Module unloaded\n");
}

/* 导出接口 */
EXPORT_SYMBOL(command_queue_add);
EXPORT_SYMBOL(command_queue_undo_last);
EXPORT_SYMBOL(create_print_command);
EXPORT_SYMBOL(create_delay_command);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel command pattern example");
module_init(command_queue_init_module);
module_exit(command_queue_exit_module);
```

## 7. 构建和测试说明

### 7.1 构建脚本
```bash
#!/bin/bash
# build-patterns.sh

echo "Building Linux kernel design pattern examples..."

# 创建构建目录
mkdir -p build

# 编译所有示例
examples=(
    "singleton-config"
    "singleton-test"
    "factory-devices"
    "factory-test"
    "observer-notifier"
    "strategy-memory"
    "command-queue"
)

for example in "${examples[@]}"; do
    echo "Building $example..."
    make TARGET="$example" clean >/dev/null 2>&1
    if make TARGET="$example" >/dev/null 2>&1; then
        echo "✓ $example built successfully"
    else
        echo "✗ $example build failed"
    fi
done

echo "Build complete!"
```

### 7.2 测试脚本
```bash
#!/bin/bash
# test-patterns.sh

echo "Testing Linux kernel design pattern examples..."

# 按顺序测试模式
echo "=== Testing Singleton Pattern ==="
sudo insmod singleton-config.ko
sudo insmod singleton-test.ko
dmesg | tail -5
sudo rmmod singleton-test
sudo rmmod singleton-config

echo "=== Testing Factory Pattern ==="
sudo insmod factory-devices.ko
sudo insmod factory-test.ko
dmesg | tail -10
sudo rmmod factory-test
sudo rmmod factory-devices

echo "=== Testing Observer Pattern ==="
sudo insmod observer-notifier.ko
dmesg | tail -10
sudo rmmod observer-notifier

echo "=== Testing Strategy Pattern ==="
sudo insmod strategy-memory.ko
dmesg | tail -20
sudo rmmod strategy-memory

echo "=== Testing Command Pattern ==="
sudo insmod command-queue.ko
dmesg | tail -15
sudo rmmod command-queue

echo "All tests completed!"
```

### 7.3 清理脚本
```bash
#!/bin/bash
# clean-patterns.sh

echo "Cleaning up kernel modules..."

# 移除所有加载的模块
sudo rmmod command-queue 2>/dev/null || true
sudo rmmod strategy-memory 2>/dev/null || true
sudo rmmod observer-notifier 2>/dev/null || true
sudo rmmod factory-test 2>/dev/null || true
sudo rmmod factory-devices 2>/dev/null || true
sudo rmmod singleton-test 2>/dev/null || true
sudo rmmod singleton-config 2>/dev/null || true

# 清理构建文件
make clean >/dev/null 2>&1

echo "Cleanup complete!"
```

## 8. 总结

本章通过完整的代码示例展示了如何在Linux内核开发中应用各种设计模式。每个示例都包含了：

1. **完整的实现代码**：展示了模式的实际应用
2. **详细的注释**：解释了设计决策和实现细节
3. **构建和测试指导**：确保代码可以正确运行
4. **最佳实践**：展示了内核环境下的模式使用技巧

通过这些实践示例，你可以：

- 理解设计模式在内核环境中的应用
- 学习如何在性能敏感的环境中使用模式
- 掌握内核开发的最佳实践
- 提高代码的可维护性和可扩展性

这些示例可以作为你自己的内核开发的参考和起点。