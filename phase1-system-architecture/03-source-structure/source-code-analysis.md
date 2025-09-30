# Linux内核源代码结构分析

## 目录
1. [主要目录详细说明](#主要目录详细说明)
2. [关键文件的作用](#关键文件的作用)
3. [架构相关代码组织](#架构相关代码组织)
4. [子系统划分原则](#子系统划分原则)
5. [代码导航示例](#代码导航示例)

## 主要目录详细说明

### 1. 顶层目录结构

```
linux-5.15/
├── arch/           # 架构相关代码
├── block/          # 块设备层
├── certs/          # 证书和签名
├── crypto/         # 加密算法
├── Documentation/  # 文档
├── drivers/        # 设备驱动
├── fs/             # 文件系统
├── include/        # 头文件
├── init/           # 内核初始化
├── ipc/            # 进程间通信
├── kernel/         # 内核核心
├── lib/            # 库函数
├── mm/             # 内存管理
├── net/            # 网络协议栈
├── samples/        # 示例代码
├── scripts/        # 构建脚本
├── security/       # 安全框架
├── sound/          # 声音子系统
├── tools/          # 用户空间工具
├── usr/            # 初始RAM磁盘
├── virt/           # 虚拟化
└── ... 更多目录
```

### 2. 架构目录 (arch/)

```c
// arch/x86/ - x86架构代码
arch/x86/
├── boot/           # 引导代码
├── entry/          # 系统调用入口
├── include/        # 架构特定头文件
├── kernel/         # 架构特定内核代码
├── lib/            # 架构特定库函数
├── mm/             # 架构特定内存管理
├── pci/            # PCI支持
├── platform/       # 平台设备
├── power/          # 电源管理
├── tools/          # 架构工具
├── video/          # 视频支持
├── xen/            # Xen虚拟化支持
└── ... 其他文件

// 架构特定Makefile示例
// arch/x86/Makefile
BITS := 32
RCX := 32

ifeq ($(CONFIG_X86_32),y)
    BITS := 32
    KBUILD_CFLAGS += -m32 -march=i686
    KBUILD_AFLAGS += -m32
    KBUILD_LDFLAGS += -m elf_i386
else
    BITS := 64
    KBUILD_CFLAGS += -m64
    KBUILD_AFLAGS += -m64
    KBUILD_LDFLAGS += -m elf_x86_64
endif

// 架构特定头文件
// arch/x86/include/asm/processor.h
struct cpuinfo_x86 {
    __u8            x86;            /* CPU family */
    __u8            x86_vendor;     /* CPU vendor */
    __u8            x86_model;
    __u8            x86_stepping;
    #ifdef CONFIG_X86_64
    /* Number of 4K pages in DTLB/ITLB combined(in pages)*/
    int             x86_tlbsize;
    #endif
    __u8            x86_vendor_id[16];
    __u8            x86_model_id[64];
    /* in KB - valid for CPUS which support this call: */
    int             x86_cache_size;
    int             x86_cache_alignment;    /* In bytes */
    /* Cache descriptors */
    struct cpu_cacheinfo x86_cacheinfo;
    int             x86_power;
    unsigned long   loops_per_jiffy;
};
```

### 3. 内核核心 (kernel/)

```c
// kernel/ 目录结构
kernel/
├── acpi/          # ACPI支持
├── audit/         # 审计子系统
├── bpf/           # BPF虚拟机
├── certs/         # 证书管理
├── configs/       # 内核配置
├── cgroup/        # 控制组
├── dma/           # DMA操作
├── events/        # 事件系统
├── exec_domain/   # 执行域
├── exit/          # 进程退出
├── fork/          # 进程创建
├── freezer/       # 进程冻结
├── futex/         # 快速用户空间互斥
├── gcov/          # 代码覆盖率
├── irq/           # 中断处理
├── irq_work/      # 中断工作
├── kallsyms/      # 符号表
├── kexec/         # kexec支持
├── kprobes/       # 动态探测
├── livepatch/     # 热补丁
├── locking/       # 锁机制
├── module/        # 模块系统
├── panic/         # 恐慌处理
├── padata/        # 并行数据
├── params/        # 参数处理
├── pid/           # PID管理
├── power/         # 电源管理
├ printk/         # 内核打印
├── profile/       # 性能分析
├── ptrace/        # 进程跟踪
├── rcu/           # RCU机制
├── reboot/        # 重启
├── relay/         # 中继系统
├── resource/      # 资源管理
├── sched/         # 调度器
├── seccomp/       # 安全计算
├── signal/        # 信号处理
├── softirq/       # 软中断
├── stacktrace/    # 栈跟踪
├── sys/           # 系统调用
├── sysctl/        # 系统控制
├── taskstats/     # 任务统计
├── time/          # 时间管理
├── timer/         # 定时器
├── trace/         # 跟踪系统
├── tsacct/        # 任务统计
├── user/          # 用户空间
└── workqueue/     # 工作队列

// 核心调度器代码
// kernel/sched/core.c
static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
    set_task_rq(p, cpu);
#ifdef CONFIG_SMP
    /*
     * After ->cpu is set up to a new value, task_rq_lock(p, ...) can be
     * successfuly executed on another CPU. We must ensure that updates of
     * per-task data have been completed by this moment.
     */
    smp_wmb();
#endif
}

void set_task_cpu(struct task_struct *p, unsigned int new_cpu)
{
    int old_cpu = task_cpu(p);

    if (old_cpu != new_cpu) {
        if (p->sched_class->migrate_task_rq)
            p->sched_class->migrate_task_rq(p, new_cpu);
        p->se.nr_migrations++;
        rseq_migrate(p);
        __set_task_cpu(p, new_cpu);
    }
}

// 进程创建代码
// kernel/fork.c
static struct task_struct *copy_process(unsigned long clone_flags,
                    unsigned long stack_start,
                    unsigned long stack_size,
                    int __user *child_tidptr,
                    struct pid *pid,
                    int trace,
                    unsigned long tls)
{
    int retval;
    struct task_struct *p;

    // 分配进程描述符
    p = dup_task_struct(current, node);
    if (!p)
        goto fork_out;

    // 初始化各个子系统
    retval = copy_semundo(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;

    retval = copy_files(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_semundo;

    retval = copy_fs(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_files;

    retval = copy_sighand(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_fs;

    retval = copy_signal(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_sighand;

    retval = copy_mm(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_signal;

    retval = copy_namespaces(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;

    retval = copy_io(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_namespaces;

    // 初始化进程状态
    p->utime = p->stime = p->gtime = 0;
    p->utimescaled = p->stimescaled = 0;
    p->prev_cputime.utime = p->prev_cputime.stime = 0;
    // ... 更多初始化
}
```

### 4. 驱动程序 (drivers/)

```c
// drivers/ 目录结构
drivers/
├── accessibility/ # 辅助功能
├── acpi/          # ACPI驱动
├── ata/           # ATA驱动
├── base/          # 驱动核心
├── block/         # 块设备驱动
├── bus/           # 总线驱动
├── cdrom/         # CD-ROM驱动
├── char/          # 字符设备驱动
├── clk/           # 时钟驱动
├── clocksource/   # 时钟源
├── connector/     # 连接器
├── cpufreq/       # CPU频率
├── cpuidle/       # CPU空闲
├── crypto/        # 加密驱动
├── devfreq/       # 设备频率
├── dma/           # DMA驱动
├── edac/          # EDAC驱动
├── eisa/          # EISA总线
├── extcon/        # 外部连接器
├── firmware/      # 固件
├── firewire/      # 火线接口
├── gpio/          # GPIO驱动
├── gpu/           # GPU驱动
├── hid/           # HID设备
├── hv/            # Hyper-V
├── i2c/           # I2C总线
├── iio/           # IIO设备
├── infiniband/    # InfiniBand
├── input/         # 输入设备
├── iommu/         # IOMMU
├── isdn/          # ISDN驱动
├── leds/          # LED驱动
├── macintosh/     # Macintosh驱动
├── mailbox/       # 邮箱
├── md/            # 多设备
├── media/         # 媒体设备
├── memory/        # 内存设备
├── message/       # 消息驱动
├── mfd/           # 多功能设备
├── misc/          # 杂项驱动
├── mmc/           # MMC/SD驱动
├── mtd/           # 内存技术设备
├── net/           # 网络设备
├── ntb/           # 非透明桥
├── nvmem/         # 非易失性内存
├── of/            # 设备树
├── parisc/        # PARISC架构
├── parport/       # 并口
├── pci/           # PCI驱动
├── pinctrl/       # 引脚控制
├── platform/      # 平台设备
├── power/         # 电源管理
├── pps/           # PPS驱动
├── ptp/           # PTP驱动
├── pwm/           # PWM驱动
├── rapidio/       # RapidIO
├── regmap/        # 寄存器映射
├── reset/         # 复位驱动
├── rpmsg/         # RPMSG
├── rtc/           # RTC驱动
├── s390/          # S390架构
├── scsi/          # SCSI驱动
├── sdio/          # SDIO驱动
├── serdev/        # 串行设备
├── spi/           # SPI总线
├── staging/       # 临时驱动
├── target/        # 目标驱动
├── thermal/       # 热管理
├── tty/           # 终端驱动
├── uio/           # 用户空间IO
├── usb/           # USB驱动
├── vhost/         # Vhost驱动
├── video/         # 视频驱动
├── virtio/        # VirtIO驱动
├── vme/           # VME总线
├── w1/            # 1-wire总线
├── watchdog/      # 看门狗
└── xen/           # Xen驱动

// 驱动核心示例
// drivers/base/core.c
struct device *device_create(struct class *class, struct device *parent,
                 dev_t devt, void *drvdata, const char *fmt, ...)
{
    va_list vargs;
    struct device *dev;

    va_start(vargs, fmt);
    dev = device_create_vargs(class, parent, devt, drvdata, NULL, fmt, vargs);
    va_end(vargs);

    return dev;
}

struct device *device_create_vargs(struct class *class, struct device *parent,
                   dev_t devt, void *drvdata,
                   const struct attribute_group **groups,
                   const char *fmt, va_list args)
{
    struct device *dev = NULL;
    int retval = -ENODEV;

    if (class == NULL || IS_ERR(class))
        goto error;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) {
        retval = -ENOMEM;
        goto error;
    }

    device_initialize(dev);
    dev->devt = devt;
    dev->class = class;
    dev->parent = parent;
    dev->groups = groups;
    dev->release = device_create_release;
    dev_set_drvdata(dev, drvdata);

    retval = kobject_set_name_vargs(&dev->kobj, fmt, args);
    if (retval)
        goto error;

    retval = device_add(dev);
    if (retval)
        goto error;

    return dev;

error:
    put_device(dev);
    return ERR_PTR(retval);
}
```

### 5. 文件系统 (fs/)

```c
// fs/ 目录结构
fs/
├── adfs/          # Acorn磁盘文件系统
├── affs/          # Amiga文件系统
├── afs/           # Andrew文件系统
├── autofs/        # 自动挂载
├── befs/          # BeOS文件系统
├── bfs/           # SCO UnixWare文件系统
├── binfmt_misc/   # 杂项二进制格式
├── btrfs/         # Btrfs文件系统
├── ceph/          # Ceph文件系统
├── cifs/          # CIFS文件系统
├── cramfs/        # 压缩RAM文件系统
├── dax/           # 直接访问
├── debugfs/       # 调试文件系统
├── devpts/        # PTS文件系统
├── ecryptfs/      # 加密文件系统
├── efivarfs/      # EFI变量文件系统
├── exfat/         # exFAT文件系统
├── ext2/          # ext2文件系统
├── ext4/          # ext4文件系统
├── f2fs/          # F2FS文件系统
├── fat/           # FAT文件系统
├── freevxfs/      # VxFS文件系统
├── fuse/          # 用户空间文件系统
├── gfs2/          # GFS2文件系统
├── hfs/           # HFS文件系统
├── hfsplus/       # HFS+文件系统
├── hostfs/        # 主机文件系统
├── hpfs/          # HPFS文件系统
├── hugetlbfs/     # 大页文件系统
├── isofs/         # ISO9660文件系统
├── jbd2/          # 日志块设备
├── jfs/           # JFS文件系统
├── minix/         # Minix文件系统
├── ncpfs/         # NCP文件系统
├── nfs/           # NFS文件系统
├── nfs_common/    # NFS通用
├── nilfs2/        # NILFS2文件系统
├── ntfs/          # NTFS文件系统
├── ocfs2/         # OCFS2文件系统
├── omfs/          # OMFS文件系统
├── openpromfs/    # OpenPROM文件系统
├── overlayfs/     # 叠加文件系统
├── proc/          # Proc文件系统
├── pstore/        # 持久存储
├── qnx4/          # QNX4文件系统
├── qnx6/          # QNX6文件系统
├── ramfs/         # RAM文件系统
├── reiserfs/      # ReiserFS文件系统
├── romfs/         # ROM文件系统
├── squashfs/      # SquashFS文件系统
├── sysfs/         # Sysfs文件系统
├── sysv/          # SystemV文件系统
├── tmpfs/         # 临时文件系统
├── ubifs/         # UBIFS文件系统
├── udf/           # UDF文件系统
├── ufs/           # UFS文件系统
├── vboxsf/        # VirtualBox共享文件夹
├── xfs/           # XFS文件系统
├── zonefs/        # Zone文件系统

// VFS层示例
// fs/inode.c
struct inode *new_inode(struct super_block *sb)
{
    struct inode *inode;

    spin_lock_prefetch(&sb->s_inode_list_lock);

    inode = alloc_inode(sb);
    if (inode) {
        spin_lock(&inode->i_lock);
        inode->i_state = 0;
        spin_unlock(&inode->i_lock);
        INIT_LIST_HEAD(&inode->i_sb_list);
        inode->__i_nrpages = 0;
        inode->i_mapping = &inode->i_data;
        inode->i_mapping->a_ops = &empty_aops;
        mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
        inode->i_mapping->host = inode;
        inode->i_mapping->flags = 0;
        atomic_set(&inode->i_writecount, 0);
        inode->i_size = 0;
        inode->i_blocks = 0;
        inode->i_bytes = 0;
        inode->i_generation = 0;
        inode->i_pipe = NULL;
        inode->i_bdev = NULL;
        inode->i_cdev = NULL;
        inode->i_link = NULL;
        inode->i_dir_seq = 0;
        inode->i_rdev = 0;
        inode->i_nlink = 1;
        inode->i_uid = 0;
        inode->i_gid = 0;
        inode->i_flags = 0;
        atomic_set(&inode->i_dio_count, 0);
        inode->i_dio_count_wb = 0;
        inode->i_wb = NULL;
        inode->i_icount = 0;
        inode->i_fop = NULL;
        inode->i_op = NULL;
        inode->i_sb = sb;
        inode->i_mapping->backing_dev_info = &sb->s_bdi;
        inode->i_data.a_ops = &empty_aops;
        INIT_HLIST_HEAD(&inode->i_dentry);
        INIT_LIST_HEAD(&inode->i_devices);
        spin_lock_init(&inode->i_lock);
        lockdep_set_class(&inode->i_lock, &sb->s_type->i_lock_key);
        init_rwsem(&inode->i_rwsem);
        INIT_LIST_HEAD(&inode->i_list);
        INIT_LIST_HEAD(&inode->i_wb_list);
        INIT_LIST_HEAD(&inode->i_lru);
        inode->i_state = I_NEW;
        spin_lock(&sb->s_inode_list_lock);
        list_add(&inode->i_sb_list, &sb->s_inodes);
        spin_unlock(&sb->s_inode_list_lock);
    }
    return inode;
}

// ext4文件系统示例
// fs/ext4/super.c
static int ext4_fill_super(struct super_block *sb, void *data, int silent)
{
    struct buffer_head *bh;
    struct ext4_super_block *es = NULL;
    struct ext4_sb_info *sbi;
    ext4_fsblk_t block;
    ext4_fsblk_t sb_block = get_sb_block(&data);
    ext4_fsblk_t logical_sb_block;
    unsigned long offset = 0;
    unsigned long journal_devnum = 0;
    unsigned long def_mount_opts;
    struct inode *root;
    const char *descr;
    int ret = -EINVAL;
    int blocksize;
    unsigned int db_count;
    unsigned int i;
    int needs_recovery, has_huge_files;
    __u64 blocks_count;
    int err;
    __le32 features;
    __u64 fsid;

    // 分配超级块信息
    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;
    sb->s_fs_info = sbi;
    sbi->s_sb = sb;

    // 解析挂载选项
    if (!parse_options((char *)data, sb, &journal_devnum, &journal_ioprio,
               NULL, 0)) {
        ret = -EINVAL;
        goto failed_mount;
    }

    // 读取超级块
    block = sb_block;
    if (block) {
        offset = do_div(block, sb->s_blocksize);
        bh = sb_bread(sb, block);
    } else {
        bh = sb_bread(sb, 0);
    }
    if (!bh) {
        ext4_msg(sb, KERN_ERR, "unable to read superblock");
        ret = -EIO;
        goto failed_mount;
    }
    es = (struct ext4_super_block *)(((char *)bh->b_data) + offset);
    sbi->s_es = es;

    // 验证超级块
    if (ext4_superblock_csum_verify(sb, es)) {
        /* Save the original superblock in case we fail to mount */
        sbi->s_es = kzalloc(sizeof(*sbi->s_es), GFP_KERNEL);
        if (!sbi->s_es) {
            ret = -ENOMEM;
            goto failed_mount;
        }
        memcpy(sbi->s_es, es, sizeof(*sbi->s_es));
    } else {
        ext4_msg(sb, KERN_ERR, "VFS: Can't find ext4 filesystem");
        goto failed_mount;
    }

    // ... 更多初始化代码
}
```

## 关键文件的作用

### 1. 顶层关键文件

```c
// Makefile - 顶层构建文件
VERSION = 5
PATCHLEVEL = 15
SUBLEVEL = 0
EXTRAVERSION = -rc1
NAME = Opossums on Parade

// .gitignore - Git忽略文件
# Top-level gitignore
*.o
*.a
*.s
*.ko
*.so
*.mod.c
*.symtypes
*.order

// CREDITS - 贡献者名单
// MAINTAINERS - 维护者信息
// COPYING - GPL许可证
// README - 内核说明

// Kbuild - 构建规则文件
# Kbuild for top-level directory of the kernel
# This file takes care of the following:
# 1) Generate bounds.h
# 2) Generate asm-offsets.h (may need bounds.h)
# 3) Generate timeconst.h
# 4) Generate verifier/bpf_dtab_netlink.h
# 5) Generate arch/x86/lib/inat-tables.c
# 6) Generate vmlinux.h (may need bounds.h and asm-offsets.h)
```

### 2. 内核初始化文件

```c
// init/main.c - 内核主初始化文件
asmlinkage __visible void __init start_kernel(void)
{
    char *command_line;
    char *after_dashes;

    set_task_stack_end_magic(&init_task);
    smp_setup_processor_id();
    debug_objects_early_init();

    cgroup_init_early();

    local_irq_disable();
    early_boot_irqs_disabled = true;

    /*
     * Interrupts are still disabled. Do necessary setups, then
     * enable them.
     */
    boot_cpu_init();
    page_address_init();
    pr_notice("%s", linux_banner);
    setup_arch(&command_line);
    mm_init_cpumask(&init_mm);
    setup_command_line(command_line);
    setup_nr_cpu_ids();
    setup_per_cpu_areas();
    boot_cpu_state_init();
    smp_prepare_boot_cpu(); /* arch-specific boot-cpu hooks */

    build_all_zonelists(NULL, NULL);
    page_alloc_init();

    pr_notice("Kernel command line: %s\n", boot_command_line);
    parse_early_param();
    after_dashes = parse_args("Booting kernel",
                  static_command_line, __start___param,
                  __stop___param - __start___param,
                  -1, -1, NULL, &unknown_bootoption);
    if (!IS_ERR_OR_NULL(after_dashes))
        parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
               NULL, set_init_arg);

    /*
     * These use large bootmem allocations and must precede
     * kmem_cache_init()
     */
    setup_log_buf(0);
    pidhash_init();
    vfs_caches_init_early();
    sort_main_extable();
    trap_init();
    mm_init();

    ftrace_init();

    /* trace_printk_init and kmem_cache_init late after cpu_online_map */
    trace_printk_init();
    kmem_cache_init();
    setup_command_line(command_line);
    setup_nr_cpu_ids();
    setup_per_cpu_areas();
    boot_cpu_state_init();
    smp_prepare_boot_cpu(); /* arch-specific boot-cpu hooks */

    rcu_init();

    /* trace_printk_init is called before kmem_cache_init */
    trace_printk_init();

    context_tracking_init();
    radix_tree_init();
    /* init some links before init_ISA_irqs() */
    early_irq_init();
    init_IRQ();
    tick_init();
    rcu_init_nohz();
    init_timers();
    hrtimers_init();
    softirq_init();
    timekeeping_init();
    time_init();
    sched_clock_postinit();
    printk_nmi_init();
    perf_event_init();
    profile_init();
    call_function_init();
    WARN(!irqs_disabled(), "Interrupts were enabled early\n");
    early_boot_irqs_disabled = false;
    local_irq_enable();

    kmem_cache_init_late();

    /*
     * HACK HACK HACK
     *
     * More arch-specific init code should be put in the appropriate
     * init level routines. This way we get the ordering right.
     */
    console_init();
    if (panic_later)
        panic("Too many boot %s vars at `%s'", panic_later,
              panic_param);

    lockdep_init();

    /*
     * Need to run this when irqs are enabled, because it wants
     * to self-test [hard/soft]-irqs on/off lock inversion bugs
     * too:
     */
    locking_selftest();

#ifdef CONFIG_BLK_DEV_INITRD
    if (initrd_start && !initrd_below_start_ok &&
        page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
        pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
            page_to_pfn(virt_to_page((void *)initrd_start)),
            min_low_pfn);
        initrd_start = 0;
    }
#endif
    page_ext_init();
    kmemleak_init();
    debug_objects_mem_init();
    setup_per_cpu_pageset();
    numa_policy_init();
    acpi_early_init();
    if (late_time_init)
        late_time_init();
    calibrate_delay();
    pidmap_init();
    anon_vma_init();
    thread_info_cache_init();
    cred_init();
    fork_init();
    proc_caches_init();
    buffer_init();
    key_init();
    security_init();
    dbg_late_init();
    vfs_caches_init();
    signals_init();
    /* rootfs populating might need page-writeback */
    page_writeback_init();
    proc_root_init();
    nsfs_init();
    cpuset_init();
    cgroup_init();
    taskstats_init_early();
    delayacct_init();

    check_bugs();

    acpi_subsystem_init();
    arch_post_acpi_subsys_init();
    sfi_init_late();
    if (efi_enabled(EFI_RUNTIME_SERVICES)) {
        efi_free_boot_services();
    }

    /* Do the rest non-__init'ed, we're now alive */
    rest_init();
}

// init/version.c - 内核版本信息
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/module.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include <linux/version.h>

#ifndef CONFIG_KALLSYMS
#define version(a) Version_ ## a
#define version_string(a) version(a)
extern int version_string(LINUX_VERSION_CODE);
int version_string(LINUX_VERSION_CODE);
#endif

struct uts_namespace init_uts_ns = {
    .kref = KREF_INIT(2),
    .name = {
        .sysname = UTS_SYSNAME,
        .nodename = UTS_NODENAME,
        .release = UTS_RELEASE,
        .version = UTS_VERSION,
        .machine = UTS_MACHINE,
        .domainname = UTS_DOMAINNAME,
    },
    .user_ns = &init_user_ns,
    .ns.inum = PROC_UTS_INIT_INO,
};
EXPORT_SYMBOL_GPL(init_uts_ns);
```

### 3. 头文件结构

```c
// include/ 目录结构
include/
├── asm-generic/   # 通用架构头文件
├── clocksource/   # 时钟源
├── config/        # 配置头文件
├── crypto/        # 加密头文件
├── drm/           # DRM头文件
├── dt-bindings/   # 设备树绑定
├── generated/     # 自动生成的头文件
├── keys/          # 密钥头文件
├── linux/         # 核心头文件
├── math-emu/      # 数学模拟
├── media/         # 媒体头文件
├── memory/        # 内存头文件
├── misc/          # 杂项头文件
├── net/           # 网络头文件
├── pcmcia/        # PCMCIA头文件
├── rdma/          # RDMA头文件
├── rxrpc/         # RxRPC头文件
├── scsi/          # SCSI头文件
├── sound/         # 声音头文件
├── target/        # 目标头文件
├── trace/         # 跟踪头文件
├── uapi/          # 用户空间API
├── video/         # 视频头文件
└── xen/           # Xen头文件

// include/linux/sched.h - 调度相关头文件
struct task_struct {
    volatile long state;    /* -1 unrunnable, 0 runnable, >0 stopped */
    void *stack;
    atomic_t usage;
    unsigned int flags;    /* per process flags, defined below */
    unsigned int ptrace;

    int lock_depth;        /* BKL lock depth */

#ifdef CONFIG_SMP
    struct llist_node wake_entry;
    int on_cpu;
#endif
    int on_rq;

    int prio, static_prio, normal_prio;
    unsigned int rt_priority;
    const struct sched_class *sched_class;
    struct sched_entity se;
    struct sched_rt_entity rt;
    struct sched_dl_entity dl;

#ifdef CONFIG_CGROUP_SCHED
    struct task_group *sched_task_group;
#endif

    struct mm_struct *mm, *active_mm;
    /* per-thread vma caching */
    u32 vmacache_seqnum;
    struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
    struct task_rss_stat    rss_stat;
#endif
/* -1 unrunnable, 0 runnable, >0 stopped: */
    volatile long state;
    void *stack;
    atomic_t usage;
    unsigned int flags;    /* per process flags, defined below */
    unsigned int ptrace;

    int lock_depth;        /* BKL lock depth */

#ifdef CONFIG_SMP
    struct llist_node wake_entry;
    int on_cpu;
#endif
    int on_rq;

    int prio, static_prio, normal_prio;
    unsigned int rt_priority;
    const struct sched_class *sched_class;
    struct sched_entity se;
    struct sched_rt_entity rt;
    struct sched_dl_entity dl;

#ifdef CONFIG_CGROUP_SCHED
    struct task_group *sched_task_group;
#endif

    struct mm_struct *mm, *active_mm;
    /* per-thread vma caching */
    u32 vmacache_seqnum;
    struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
    struct task_rss_stat    rss_stat;
#endif

    /* Task credentials */
    const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
    const struct cred __rcu *real_cred;   /* objective and real subjective task
                         credentials (COW) */
    const struct cred __rcu *cred;    /* effective (overridable) subjective task
                         credentials (COW) */
    char comm[TASK_COMM_LEN]; /* executable name excluding path
                     - access with [gs]et_task_comm (which lock
                       it with task_lock())
                     - initialized normally by setup_new_exec */
    /* file system information */
    struct fs_struct *fs;
    /* open file information */
    struct files_struct *files;
    /* namespaces */
    struct nsproxy *nsproxy;
    /* signal handlers */
    struct signal_struct *signal;
    struct sighand_struct *sighand;
    sigset_t blocked, real_blocked;
    sigset_t saved_sigmask; /* restored if set_restore_sigmask() was used */
    struct sigpending pending;
    unsigned long sas_ss_sp;
    size_t sas_ss_size;
    unsigned int sas_ss_flags;

    struct callback_head *task_works;

    struct audit_context *audit_context;
#ifdef CONFIG_AUDITSYSCALL
    kuid_t loginuid;
    unsigned int sessionid;
#endif

    struct seccomp seccomp;

    /* Thread group tracking */
    u32 parent_exec_id;
    u32 self_exec_id;

    /* Protection of (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed,
     * mempolicy */
    spinlock_t alloc_lock;

    /* Protection of the PI data structures: */
    raw_spinlock_t pi_lock;

    struct wake_q_node wake_q;

#ifdef CONFIG_RT_MUTEXES
    /* PI waiters blocked on a rt_mutex held by this task */
    struct rb_root_cached pi_waiters;
    /* Deadlock detection and priority inheritance handling */
    struct rt_mutex_waiter *pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
    /* Mutex deadlock detection */
    struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
    unsigned int irq_events;
    unsigned long hardirq_enable_ip;
    unsigned long hardirq_disable_ip;
    unsigned int hardirq_enable_event;
    unsigned int hardirq_disable_event;
    int hardirqs_enabled;
    int hardirq_context;
    unsigned long softirq_disable_ip;
    unsigned long softirq_enable_ip;
    unsigned int softirq_disable_event;
    unsigned int softirq_enable_event;
    int softirqs_enabled;
    int softirq_context;
#endif

#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
    u64 curr_chain_key;
    int lockdep_depth;
    unsigned int lockdep_recursion;
    struct held_lock held_locks[MAX_LOCK_DEPTH];
#endif

/* journalling filesystem info */
    void *journal_info;

/* stacked block device info */
    struct bio_list *bio_list;

#ifdef CONFIG_BLOCK
    /* stack plugging */
    struct blk_plug *plug;
#endif

/* VM state */
    struct reclaim_state *reclaim_state;

    struct backing_dev_info *backing_dev_info;

    struct io_context *io_context;
    unsigned long ptrace_message;
    siginfo_t *last_siginfo; /* For ptrace use.  */
    struct task_io_accounting ioac;
#ifdef CONFIG_TASK_XACCT
    u64 acct_rss_mem1;    /* accumulated rss usage */
    u64 acct_vm_mem1;    /* accumulated virtual memory usage */
    cputime_t acct_timexpd;    /* stime + utime since last update */
#endif
#ifdef CONFIG_CPUSETS
    nodemask_t mems_allowed;    /* Protected by alloc_lock */
    seqcount_t mems_allowed_seq;    /* Seqence no. for mems_allowed updates */
    int cpuset_mem_spread_rotor;
    int cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
    /* Control Group info protected by css_set_lock */
    struct css_set __rcu *cgroups;
    struct list_head cg_list;
#endif
#ifdef CONFIG_CGROUP_SCHED
    struct task_group *sched_task_group;
#endif
#ifdef CONFIG_SYSCTL
    struct sysctl_key_set *sysctl_key_set;
#endif
#ifdef CONFIG_PERF_EVENTS
    struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
    struct mutex perf_event_mutex;
    struct list_head perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
    unsigned long preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
    struct mempolicy *mempolicy;    /* Protected by alloc_lock */
    short il_next;
    short pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
    int numa_scan_seq;
    unsigned int numa_scan_period;
    unsigned int numa_scan_period_max;
    int numa_preferred_nid;
    unsigned long numa_migrate_retry;
    u64 node_stamp;            /* migration stamp  */
    u64 last_task_numa_placement;
    u64 last_sum_exec_runtime;
    struct callback_head numa_work;
#endif /* CONFIG_NUMA_BALANCING */

    struct rcu_head rcu;

    /*
     * New fields for task_struct should be added above here, so that
     * they are included in the randomized portion of task_struct.
     */
    struct list_head tasks;
#ifdef CONFIG_THREAD_INFO_IN_TASK
    /*
     * For reasons of header soup (see current_thread_info()), this
     * must be the first element of task_struct.
     */
    struct thread_info thread_info;
#endif
};
```

## 架构相关代码组织

### 1. 架构特定目录

```c
// arch/x86/ 目录结构
arch/x86/
├── boot/           # 引导代码
│   ├── compressed/ # 解压缩代码
│   └── tools/      # 引导工具
├── entry/          # 系统调用和中断入口
│   ├── common/     # 通用入口
│   ├── 32/         # 32位入口
│   └── 64/         # 64位入口
├── include/        # x86头文件
│   ├── asm/        # 汇编头文件
│   ├── generated/  # 生成的头文件
│   └── uapi/       # 用户空间API
├── kernel/         # x86内核代码
│   ├── acpi/       # ACPI支持
│   ├── apic/       # APIC支持
│   ├── cpu/        # CPU特定
│   ├── fpu/        # FPU支持
│   ├── kprobes/    # Kprobes支持
│   ├── tsc/        # TSC支持
│   └── traps/      # 陷阱处理
├── lib/            # x86库函数
├── mm/             # x86内存管理
│   ├── kasan/      # KASAN支持
│   ├── init_32.c   # 32位初始化
│   ├── init_64.c   # 64位初始化
│   ├── pgtable_32.c # 32位页表
│   └── pgtable_64.c # 64位页表
├── pci/            # PCI支持
├── platform/       # 平台设备
├── power/          # 电源管理
├── tools/          # x86工具
├── video/          # 视频支持
└── xen/            # Xen虚拟化

// 架构特定系统调用入口
// arch/x86/entry/entry_64.S
ENTRY(entry_SYSCALL_64)
    /* Construct struct pt_regs on stack */
    pushq   %rcx                        /* pt_regs->ip */
    pushq   %r11                        /* pt_regs->flags */
    pushq   $__USER_CS                  /* pt_regs->cs */
    pushq   %rcx                        /* pt_regs->ip */
    pushq   %rax                        /* pt_regs->orig_ax */
    pushq   %rdi                        /* pt_regs->di */
    pushq   %rsi                        /* pt_regs->si */
    pushq   %rdx                        /* pt_regs->dx */
    pushq   %rcx                        /* pt_regs->cx */
    pushq   $-ENOSYS                    /* pt_regs->ax */
    pushq   %r8                         /* pt_regs->r8 */
    pushq   %r9                         /* pt_regs->r9 */
    pushq   %r10                        /* pt_regs->r10 */
    pushq   %r11                        /* pt_regs->r11 */
    sub $(6*8), %rsp                    /* pt_regs->bp, bx, r12-15 not saved */

    /* IRQs are off. */
    movq    %rsp, %rdi
    call    do_syscall_64           /* returns with IRQs off */

    /* 0(%rsp): return code */
    jmp     return_from_SYSCALL_64
END(entry_SYSCALL_64)

// 架构特定内存管理
// arch/x86/mm/init_64.c
void __init mem_init(void)
{
    pci_iommu_alloc();

    /* clear_bss() already clear the empty_zero_page */
    empty_zero_page = virt_to_page(empty_zero_page);

    /* this will put all low memory onto the freelists */
    free_all_bootmem();
    after_bootmem = 1;

    /* Register memory areas for /proc/kcore */
    kclist_add(&kcore_vsyscall, (void *)VSYSCALL_ADDR,
               PAGE_SIZE, KCORE_USER);

    mem_init_print_info(NULL);
}

// 架构特定初始化
// arch/x86/kernel/setup.c
void __init setup_arch(char **cmdline_p)
{
    /*
     * copy kernel command line
     */
    *cmdline_p = boot_command_line;

    /*
     * If we have OLPC OFW, we might need to do a special setup
     * for the framebuffer.  This should go before any of the
     * normal console initialization.
     */
    olpc_ofw_detect();

    early_cpu_init();
    early_ioremap_init();

    setup_arch_memblock();
    setup_memory_map();
    parse_setup_data();
    copy_edd();

    if (!boot_params.hdr.version)
        copy_edd();

    strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
    *cmdline_p = command_line;

    parse_early_param();

    /* after early param, so could get panic from serial */
    setup_real_mode();

    trap_init();
    early_cpu_init();
    init_gbpages();
    memblock_set_current_limit(ISA_END_ADDRESS);

    /*
     * At this point everything still needed from the boot loader
     * or BIOS or kernel text should be early reserved or marked not
     * present in the memblock.memory map so that it won't get
     * allocated by the buddy allocator.
     */
    x86_init.paging.pagetable_init();
    x86_init.hyper.init_platform();

    /*
     * Update mmu_cr4_features (and, indirectly, trampoline_cr4_features)
     * with the current CR4 value.
     */
    mmu_cr4_features = __read_cr4();

    /*
     * This needs to be called before any device driver setup calls
     * (e.g. x86_init.pci.init_irq())
     */
    x86_init.resources.probe_roms();

    /* after parse_early_param, so could get panic from serial */
    reserve_ibft_region();

    /*
     * Find free reservations for standard resources
     */
    x86_init.resources.reserve_resources();

    e820__reserve_resources();
    e820__register_nosave_regions(max_low_pfn);

    x86_init.paging.pagetable_init();

    /*
     * Do this before parse_early_param() so that EDD/MPTABLE
     * setup run early enough.
     */
    x86_init.oem.arch_setup();

    iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;

    setup_bios_corruption_check();
    setup_arch_gart();
    setup_swiotlb();
}
```

### 2. 通用架构支持

```c
// arch/ 下的通用架构支持
arch/alpha/        # Alpha架构
arch/arc/          # ARC架构
arch/arm/          # ARM架构
arch/arm64/        # ARM64架构
arch/c6x/          # C6x架构
arch/csky/         # C-SKY架构
arch/h8300/        # H8/300架构
arch/hexagon/      # Hexagon架构
arch/ia64/         # IA-64架构
arch/m68k/         # m68k架构
arch/microblaze/   # MicroBlaze架构
arch/mips/         # MIPS架构
arch/nds32/        # NDS32架构
arch/nios2/        # Nios II架构
arch/openrisc/     # OpenRISC架构
arch/parisc/       # PA-RISC架构
arch/powerpc/      # PowerPC架构
arch/riscv/        # RISC-V架构
arch/s390/         # S390架构
arch/sh/           # SuperH架构
arch/sparc/        # SPARC架构
arch/um/           # 用户模式Linux
arch/x86/          # x86架构
arch/xtensa/       # Xtensa架构

// 通用架构头文件
// include/asm-generic/
├── atomic.h       # 原子操作
├── barrier.h      # 内存屏障
├── bitops.h       # 位操作
├── bugs.h         # 错误处理
├── cputime.h      # CPU时间
├── div64.h        # 64位除法
├── dma.h          # DMA操作
├── emergency-restart.h # 紧急重启
├── errno.h        # 错误码
├── fb.h           # 帧缓冲
├── fcntl.h        # 文件控制
├── futex.h        # Futex操作
├── hw_irq.h       # 硬件中断
├── io.h           # IO操作
├── ioctl.h        # IO控制
├── ioctls.h       # IO控制命令
├── ipcbuf.h       # IPC缓冲区
├── irq_regs.h    # 中断寄存器
├── irqflags.h     # 中断标志
├── kdebug.h       # 内核调试
├── kmap_types.h   # 映射类型
├── linkage.h      # 链接属性
├── local.h        # 本地操作
├── mman-common.h  # 内存管理
├── msi.h          # MSI中断
├── mutex.h        # 互斥锁
├── pci.h          # PCI支持
├── percpu.h       # 每CPU变量
├── pgalloc.h      # 页面分配
├── pgtable.h      # 页表
├── poll.h         # 轮询
├── posix_types.h  # POSIX类型
├── resource.h     # 资源管理
├── sections.h     # 段定义
├── sembuf.h       # 信号量缓冲
├── setup.h        # 设置
├── shmbuf.h       # 共享内存缓冲
├── siginfo.h      # 信号信息
├── signal.h       # 信号处理
├── socket.h       # 套接字
├── sockios.h      # 套接字IO
├── stat.h         # 文件状态
├── statfs.h       # 文件系统状态
├── termbits.h     # 终端位
├── termios.h      # 终端IO
├── topology.h     # 拓扑
├── types.h        # 类型定义
├── uaccess.h      # 用户空间访问
├── ucontext.h     # 用户上下文
├── ucontext-common.h # 通用用户上下文
├── unaligned.h    # 未对齐访问
└── xor.h          # XOR操作
```

## 子系统划分原则

### 1. 分层架构

```c
// 网络子系统分层
net/
├── core/          # 核心网络功能
├── ipv4/          # IPv4协议
├── ipv6/          # IPv6协议
├── netfilter/     # 防火墙
├── sched/         # 调度算法
├── wireless/      # 无线网络
├── ethernet/      # 以太网
└── 802/           # 802协议

// 网络分层示例
// net/core/dev.c - 网络设备层
static int __init net_dev_init(void)
{
    int i, rc = -ENOMEM;

    BUG_ON(!dev_boot_phase);

    if (dev_proc_init())
        goto out;

    if (netdev_kobject_init())
        goto out;

    INIT_LIST_HEAD(&ptype_all);
    for (i = 0; i < PTYPE_HASH_SIZE; i++)
        INIT_LIST_HEAD(&ptype_base[i]);

    INIT_LIST_HEAD(&offload_base);

    if (register_pernet_subsys(&netdev_net_ops))
        goto out;

    /*
     * Initialise the packet receive queues.
     */
    for_each_possible_cpu(i) {
        struct softnet_data *sd = &per_cpu(softnet_data, i);

        skb_queue_head_init(&sd->input_pkt_queue);
        skb_queue_head_init(&sd->process_queue);
        INIT_LIST_HEAD(&sd->poll_list);
        sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
        sd->csd.func = rps_trigger_softirq;
        sd->csd.info = sd;
        sd->cpu = i;
#endif
        sd->received_rps = 0;
        sd->drop_queue = NULL;
        INIT_WORK(&sd->backlog_work, process_backlog);
        sd->backlog.weight = weight_p;
    }

    dev_boot_phase = 0;

    /* The loopback device is special if any other network devices
     * is present in a network namespace the loopback device must
     * be present. Since we now dynamically allocate and free the
     * loopback device make sure there is always one present.
     */
    if (register_pernet_device(&loopback_net_ops))
        goto out;

    if (register_pernet_device(&default_device_ops))
        goto out;

    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
    open_softirq(NET_RX_SOFTIRQ, net_rx_action);

    hotcpu_notifier(dev_cpu_callback, 0);
    dst_subsys_init();
    rc = 0;
out:
    return rc;
}

// 协议层
// net/ipv4/af_inet.c - IPv4协议族
static int __init inet_init(void)
{
    struct inet_protosw *q;
    struct list_head *r;
    int rc = -EINVAL;

    BUILD_BUG_ON(sizeof(struct inet_skb_parm) > FIELD_SIZEOF(struct sk_buff, cb));

    sysctl_local_reserved_ports = kzalloc(65536 / sizeof(u16), GFP_KERNEL);
    if (!sysctl_local_reserved_ports)
        goto out;

    rc = proto_register(&tcp_prot, 1);
    if (rc)
        goto out_free_reserved_ports;

    rc = proto_register(&udp_prot, 1);
    if (rc)
        goto out_unregister_tcp_proto;

    rc = proto_register(&raw_prot, 1);
    if (rc)
        goto out_unregister_udp_proto;

    rc = proto_register(&ping_prot, 1);
    if (rc)
        goto out_unregister_raw_proto;

    /*
     * Tell SOCKET that we are alive...
     */
    (void)sock_register(&inet_family_ops);

#ifdef CONFIG_SYSCTL
    ip_static_sysctl_init();
#endif

    /*
     * Add all the base protocols.
     */

    if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
        pr_crit("%s: Cannot add ICMP protocol\n", __func__);
    if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
        pr_crit("%s: Cannot add UDP protocol\n", __func__);
    if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
        pr_crit("%s: Cannot add TCP protocol\n", __func__);
#ifdef CONFIG_IP_MULTICAST
    if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
        pr_crit("%s: Cannot add IGMP protocol\n", __func__);
#endif

    /* Register the socket-side information for inet_create. */
    for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
        INIT_LIST_HEAD(r);

    for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
        inet_register_protosw(q);

    /*
     * Set the ARP module up
     */

    arp_init();

    /*
     * Set the IP module up
     */

    ip_init();

    /* Setup TCP slab cache for open requests. */
    tcp_init();

    /* Setup UDP memory threshold */
    udp_init();

    raw_init();

    /*
     * Set the ICMP layer up
     */

    icmp_init(&inet_sock_ops);

    /*
     * Initialise the multicast router
     */
#if defined(CONFIG_IP_MROUTE)
    if (ip_mr_init())
        pr_crit("%s: Cannot init ipv4 mroute\n", __func__);
#endif

    if (init_inet_pernet_ops())
        pr_crit("%s: Cannot init ipv4 pernet ops\n", __func__);

    /*
     *  Initialise per-cpu ipv4 mibs
     */

    if (init_ipv4_mibs())
        pr_crit("%s: Cannot init ipv4 mibs\n", __func__);

    ip_misc_proc_init();

    rc = 0;
out:
    return rc;
out_unregister_raw_proto:
    proto_unregister(&raw_prot);
out_unregister_udp_proto:
    proto_unregister(&udp_prot);
out_unregister_tcp_proto:
    proto_unregister(&tcp_prot);
out_free_reserved_ports:
    kfree(sysctl_local_reserved_ports);
    goto out;
}
```

### 2. 模块化设计

```c
// 内存管理模块化
mm/
├── filemap.c      # 文件映射
├── memory.c       # 内存管理
├── mmap.c         # 内存映射
├── mprotect.c     # 内存保护
├── mremap.c       # 内存重映射
├── msync.c        # 内存同步
├── page_alloc.c   # 页面分配
├── page_io.c      # 页面IO
├── readahead.c    # 预读取
├── swap.c         # 交换空间
├── swap_state.c   # 交换状态
├── swapfile.c     # 交换文件
├── truncate.c     # 截断
├── vmscan.c       # 内存回收
└── vmalloc.c      # 虚拟内存分配

// 内存分配器示例
// mm/page_alloc.c
struct page *__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
                    int preferred_nid, nodemask_t *nodemask)
{
    struct page *page;
    unsigned int alloc_flags = ALLOC_WMARK_LOW;
    gfp_t alloc_mask = gfp_mask;
    struct alloc_context ac = { };

    /*
     * There are several places where we assume that the order
     * is a power-of-two.  Check that this is the case.
     */
    VM_BUG_ON(order && !is_power_of_2(order));

    gfp_mask &= gfp_allowed_mask;

    /*
     * Apply this allocation's GFP flags to the per-process
     * allocation flags.  The GFP flags are changed for
     * each allocation call, but the process flags are
     * constant for the entire process.
     */
    alloc_mask |= __GFP_HARDWALL;

    /*
     * The preferred zone is used for statistics but crucially it is
     * also used as the starting point for the zonelist iterator.
     * It may get reset for allocations that ignore cpuset policies.
     */
    ac.preferred_zoneref = first_zones_zonelist(zonelist, highest_zoneidx,
                &ac.nodemask);
    if (!ac.preferred_zoneref) {
        /*
         * There is no guarantee that the preferred zoneref can
         * satisfy the request so we fallback to the first
         * available zone.
         */
        ac.preferred_zoneref = first_zones_zonelist(zonelist, highest_zoneidx,
                    NULL);
        if (!ac.preferred_zoneref) {
            page = NULL;
            goto no_zone;
        }
    }

    page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
    if (page)
        goto out;

    /*
     * If this is a high-order allocation, and __GFP_DIRECT_RECLAIM has
     * been exhausted, then try compaction.
     */
    if (order > 0 && alloc_flags & ALLOC_CPUSET) {
        page = __alloc_pages_direct_compact(gfp_mask, order,
                        alloc_flags, ac.preferred_zoneref,
                        alloc_mask, &ac);
        if (page)
            goto out;
    }

    /*
     * If we are likely to get page reclaim or compaction then
     * do it now rather than wait for kswapd to catch up.
     */
    if (alloc_flags & ALLOC_KSWAPD) {
        page = __alloc_pages_direct_reclaim(gfp_mask, order,
                        alloc_flags, &ac);
        if (page)
            goto out;
    }

    /* Check if we should retry the allocation */
    page = __alloc_pages_slowpath(gfp_mask, order, &ac);

out:
    if (memcg_kmem_enabled() && (gfp_mask & __GFP_ACCOUNT) && page &&
        unlikely(memcg_kmem_charge(page, gfp_mask, order) != 0)) {
        __free_pages(page, order);
        page = NULL;
    }

    return page;
}
```

### 3. 接口分离

```c
// 虚拟文件系统接口
// fs/filesystems.c
struct file_system_type {
    const char *name;
    int fs_flags;
    struct dentry *(*mount) (struct file_system_type *, int,
               const char *, void *);
    void (*kill_sb) (struct super_block *);
    struct module *owner;
    struct file_system_type * next;
    struct hlist_head fs_supers;

    struct lock_class_key s_lock_key;
    struct lock_class_key s_umount_key;
    struct lock_class_key s_vfs_rename_key;
    struct lock_class_key s_writers_key[SB_FREEZE_LEVELS];

    struct lock_class_key i_lock_key;
    struct lock_class_key i_mutex_key;
    struct lock_class_key i_mutex_dir_key;
};

int register_filesystem(struct file_system_type * fs)
{
    int res = 0;
    struct file_system_type ** p;

    BUG_ON(!fs);
    BUG_ON(!fs->name);

    if (fs->next)
        return -EBUSY;
    write_lock(&file_systems_lock);
    p = find_filesystem(fs->name, strlen(fs->name));
    if (*p)
        res = -EBUSY;
    else
        *p = fs;
    write_unlock(&file_systems_lock);
    return res;
}

// 设备驱动接口
// include/linux/device.h
struct bus_type {
    const char      *name;
    const char      *dev_name;
    struct device       *dev_root;
    struct device_attribute *dev_attrs;   /* use dev_groups instead */
    const struct attribute_group **bus_groups;
    const struct attribute_group **dev_groups;
    const struct attribute_group **drv_groups;

    int (*match)(struct device *dev, struct device_driver *drv);
    int (*uevent)(struct device *dev, struct kobj_uevent_env *env);
    int (*probe)(struct device *dev);
    int (*remove)(struct device *dev);
    void (*shutdown)(struct device *dev);

    int (*online)(struct device *dev);
    int (*offline)(struct device *dev);

    int (*suspend)(struct device *dev, pm_message_t state);
    int (*resume)(struct device *dev);

    const struct dev_pm_ops *pm;

    struct iommu_ops *iommu_ops;

    struct subsys_private *p;
    struct lock_class_key lock_key;
};
```

## 代码导航示例

### 1. 函数查找方法

```bash
# 使用ctags生成索引
ctags -R .

# 查找函数定义
grep -r "function_name" include/
grep -r "function_name" kernel/

# 使用cscope
cscope -R
# 然后使用cscope的交互界面查找

# 使用kernel.org的代码搜索
# https://elixir.bootlin.com/linux/latest/ident/function_name
```

### 2. 数据结构追踪

```c
// 从进程创建到调度执行的路径追踪

// 1. fork系统调用
// kernel/fork.c
SYSCALL_DEFINE0(fork)
{
    struct kernel_clone_args args = {
        .flags = SIGCHLD,
    };

    return _do_fork(&args);
}

// 2. 进程创建
// kernel/fork.c
static struct task_struct *copy_process(unsigned long clone_flags,
                    unsigned long stack_start,
                    unsigned long stack_size,
                    int __user *child_tidptr,
                    struct pid *pid,
                    int trace,
                    unsigned long tls)
{
    struct task_struct *p;
    int retval;

    // 分配进程描述符
    p = dup_task_struct(current, node);
    if (!p)
        goto fork_out;

    // 初始化各个子系统
    retval = copy_files(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;

    retval = copy_fs(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_files;

    // ... 更多初始化

    // 唤醒新进程
    wake_up_new_task(p);

    return p;
}

// 3. 进程调度
// kernel/sched/core.c
void wake_up_new_task(struct task_struct *p)
{
    struct rq_flags rf;
    struct rq *rq;

    raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
    p->state = TASK_RUNNING;
    raw_spin_unlock_irqrestore(&p->pi_lock, rf.flags);

    // 获取运行队列
    rq = this_rq();
    raw_spin_lock_irqsave(&rq->lock, rf.flags);

    // 添加到运行队列
    p->sched_class->enqueue_task(rq, p, 0);
    // 检查是否需要抢占
    if (task_new && !dl_task(p))
        check_preempt_curr(rq, p, 0);

    raw_spin_unlock_irqrestore(&rq->lock, rf.flags);
}

// 4. 调度器选择
// kernel/sched/core.c
void __sched schedule(void)
{
    struct task_struct *prev, *next;
    struct rq *rq;
    unsigned long *switch_count;
    struct rq_flags rf;

    // 禁用中断
    local_irq_disable();
    // 获取运行队列
    rq = this_rq();

    // 获取当前任务
    prev = rq->curr;
    schedule_debug(prev);

    // 调度前处理
    if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
        if (unlikely(signal_pending_state(prev->state, prev))) {
            prev->state = TASK_RUNNING;
        } else {
            deactivate_task(rq, prev, DEQUEUE_SLEEP);
            prev->on_rq = 0;
        }
        switch_count = &prev->nvcsw;
    }

    // 选择下一个任务
    next = pick_next_task(rq, prev, &rf);
    clear_tsk_need_resched(prev);
    clear_preempt_need_resched();

    // 切换任务
    if (likely(prev != next)) {
        rq->nr_switches++;
        rq->curr = next;
        ++*switch_count;

        context_switch(rq, prev, next, &rf);
    } else {
        rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);
        rq_unlock_irq(rq, &rf);
    }
}
```

### 3. 配置项追踪

```bash
# 追踪配置选项
grep -r "CONFIG_SMP" include/
grep -r "CONFIG_SMP" arch/
grep -r "CONFIG_SMP" kernel/

# 查看配置选项的定义
grep -r "config SMP" arch/x86/Kconfig
grep -r "config SMP" kernel/Kconfig*

# 查看配置选项的使用
grep -r "#ifdef CONFIG_SMP" .
grep -r "#if CONFIG_SMP" .
```

### 4. 编译错误调试

```bash
# 构建特定文件
make drivers/char/random.o

# 显示详细构建信息
make V=1

# 显示预处理结果
make drivers/char/random.i

# 显示汇编代码
make drivers/char/random.s

# 使用 sparse 进行静态分析
make C=1 drivers/char/random.o
```

## 总结

Linux内核源代码的组织结构反映了其模块化、层次化的设计理念。通过理解目录结构、关键文件的作用以及架构相关代码的组织方式，可以更有效地导航和理解内核代码。

子系统划分原则体现了内核的设计哲学：清晰的接口分离、模块化的组件设计、以及统一的抽象层。这些原则使得内核代码既易于理解又易于维护。

通过掌握代码导航的方法和技巧，开发者可以更快地定位和理解内核代码，为后续的内核开发、调试和优化工作打下坚实的基础。