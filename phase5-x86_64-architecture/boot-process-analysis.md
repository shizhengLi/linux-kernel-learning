# x86_64启动过程和模式转换深度分析

## 概述
x86_64架构的启动过程是一个复杂的多阶段过程，涉及从实模式到长模式的转换。本文基于Linux 6.17内核源代码，详细分析x86_64系统的启动流程和模式转换机制。

## 1. 启动过程概述

### 1.1 启动阶段划分

x86_64系统的启动过程可以分为以下主要阶段：

1. **硬件初始化**：BIOS/UEFI自检
2. **引导加载程序**：Bootloader加载内核
3. **实模式初始化**：16位实模式代码执行
4. **保护模式切换**：从实模式到32位保护模式
5. **长模式激活**：从保护模式到64位长模式
6. **内核初始化**：64位内核启动

### 1.2 关键源码文件

```
arch/x86/
├── boot/                    # 实模式引导代码
│   ├── main.c              # 主引导程序
│   ├── pmjump.S            # 保护模式跳转
│   └── header.S            # 引导头
├── compressed/              # 内核压缩代码
│   ├── head_64.S           # 64位启动代码
│   └── misc.c              # 压缩/解压函数
├── kernel/                  # 内核启动代码
│   ├── head_64.S           # 64位内核入口
│   └── main.c              # 内核主初始化
└── entry/                   # 系统调用和异常入口
    ├── entry_64.S          # 64位系统调用入口
    └── syscall_64.c        # 系统调用处理
```

## 2. 实模式阶段

### 2.1 引导头结构

```c
// arch/x86/boot/header.S
setup_header:
    .ascii  "HdrS"          // 引导头签名
    .word   0x0202          // 协议版本
    .long   0               // 实模式代码起始地址
    .byte   0               // 启动扇区加载标志
    .byte   0               // 引导模式标志
    .word   (syssize - 512 + 15) / 16 // 实模式代码段大小
    .long   0               // 引导入口点
    .long   0               // 初始化堆栈段
    .long   0               // 初始化堆栈指针
    .long   0               // 堆段结束地址
    .long   0               // 堆段起始地址
    .long   0               // 加载高位地址
```

### 2.2 实模式主程序

```c
// arch/x86/boot/main.c
void main(void)
{
    /* 初始化默认I/O操作 */
    init_default_io_ops();

    /* 复制引导参数 */
    copy_boot_params();

    /* 初始化控制台 */
    console_init();

    /* 初始化堆 */
    init_heap();

    /* 验证CPU支持 */
    validate_cpu();

    /* 检测内存布局 */
    detect_memory();

    /* 设置键盘 */
    keyboard_init();

    /* 设置鼠标 */
    enable_mouse();

    /* 进入保护模式 */
    go_to_protected_mode();
}
```

### 2.3 内存检测

```c
// arch/x86/boot/memory.c
int detect_memory(void)
{
    int err = -1;

    /* 检测扩展内存 */
    detect_memory_e820();

    /* 检测扩展BIOS数据区 */
    detect_memory_ext();

    /* 检测标准内存 */
    detect_memory_88();

    return err;
}

/* E820内存映射检测 */
static int detect_memory_e820(void)
{
    int count = 0;
    struct biosregs ireg, oreg;
    struct e820entry *desc = boot_params.e820_map;
    static struct e820entry buf; /* static so it is zeroed */

    initregs(&ireg);
    ireg.ax = 0xe820;
    ireg.cx = sizeof(buf);
    ireg.edx = SMAP;
    ireg.di = (size_t)&buf;

    /*
     * 注意：某些BIOS在第一次调用时会返回错误。
     * 我们重试一次以确保准确性。
     */
    do {
        intcall(0x15, &ireg, &oreg);
        if (oreg.eflags & X86_EFLAGS_CF)
            break;

        if (oreg.eax == SMAP) {
            *desc++ = buf;
            count++;
        } else {
            /* 某些BIOS不返回SMAP标记 */
            break;
        }

        ireg.bx = oreg.bx;
    } while (ireg.bx && count < ARRAY_SIZE(boot_params.e820_map));

    return boot_params.e820_entries = count;
}
```

## 3. 保护模式切换

### 3.1 保护模式准备

```c
// arch/x86/boot/pm.c
void go_to_protected_mode(void)
{
    /* 检查CPU是否支持保护模式 */
    if (cpu_has_pae())
        enable_a20();
    else
        die("Sorry, your CPU doesn't support PAE\n");

    /* 启用A20地址线 */
    if (!enable_a20())
        die("Failed to enable A20 gate\n");

    /* 重新编程PIC */
    mask_all_interrupts();

    /* 设置IDT */
    setup_idt();

    /* 设置GDT */
    setup_gdt();

    /* 切换到保护模式 */
    protected_mode_jump(boot_params.hdr.code32_start,
                       (u32)&boot_params + (ds() << 4));
}
```

### 3.2 GDT设置

```c
// arch/x86/boot/pm.c
static void setup_gdt(void)
{
    /* GDT指针和大小 */
    gdt.r_limit = gdt_size - 1;
    gdt.r_base = (size_t)&gdt;

    /* 复制GDT */
    memcpy(gdt.table, boot_gdt, sizeof(boot_gdt));
}

/* 标准GDT定义 */
static const u64 boot_gdt[] __aligned(8) = {
    [GDT_ENTRY_NULL]          = 0,
    [GDT_ENTRY_BOOT_CS]       = GDT_ENTRY(0xc09b, 0, 0xfffff),
    [GDT_ENTRY_BOOT_DS]       = GDT_ENTRY(0xc093, 0, 0xfffff),
    [GDT_ENTRY_BOOT_TSS]      = GDT_ENTRY(0x0089, 4096, 0),
};
```

### 3.3 保护模式跳转

```c
// arch/x86/boot/pmjump.S
SYM_FUNC_START_NOALIGN(protected_mode_jump)
    /* 保存引导参数指针到esi */
    movl    %edx, %esi

    /* 设置数据段选择子 */
    movw    $__BOOT_DS, %cx

    /* 读取CR0，设置保护模式位 */
    movl    %cr0, %edx
    orb     $X86_CR0_PE, %dl
    movl    %edx, %cr0

    /* 使用远跳转进入32位模式 */
    .byte   0x66, 0xea    /* ljmpl opcode */
    .long   .Lin_pm32
    .word   __BOOT_CS
.Lin_pm32:
    /* 设置32位数据段 */
    movl    %ecx, %ds
    movl    %ecx, %es
    movl    %ecx, %fs
    movl    %ecx, %gs
    movl    %ecx, %ss

    /* 调用32位入口点 */
    jmp     *%edi
SYM_FUNC_END(protected_mode_jump)
```

## 4. 长模式激活

### 4.1 64位启动代码

```c
// arch/x86/boot/compressed/head_64.S
    .text
    .globl  startup_32
startup_32:
    /* 清除方向标志 */
    cld

    /* 禁用中断 */
    cli

    /* 设置段寄存器 */
    movl    $__BOOT_DS, %eax
    movl    %eax, %ds
    movl    %eax, %es
    movl    %eax, %ss

    /* 设置栈 */
    leal    (boot_stack_end)(%ebx), %esp

    /* 调用解压缩函数 */
    call    decompress_kernel

    /* 跳转到解压后的内核 */
    jmp     *%ebp
```

### 4.2 长模式初始化

```c
// arch/x86/boot/compressed/head_64.S
SYM_CODE_START(startup_64)
    /* 64位入口点 */
    UNWIND_HINT_EMPTY
    /* 确保我们处于64位模式 */
    testl   $1, %cs
    jnz     .Lbad_address

    /* 设置数据段 */
    movl    $__KERNEL_DS, %eax
    movl    %eax, %ds
    movl    %eax, %es
    movl    %eax, %ss
    movl    %eax, %fs
    movl    %eax, %gs

    /* 设置栈 */
    leaq    (__end)(%rbp), %rsp

    /* 调用主初始化函数 */
    call    x86_64_start_kernel
SYM_CODE_END(startup_64)
```

### 4.3 分页机制初始化

```c
// arch/x86/boot/compressed/head_64.S
    /* 设置初始页表 */
    leaq    rva(pgtable)(%rbx), %rdi
    movq    %rdi, %cr3

    /* 启用PAE分页 */
    movl    $(X86_CR0_PG | X86_CR0_WP | X86_CR0_PE), %eax
    movl    %eax, %cr0

    /* 启用长模式 */
    movl    $MSR_EFER, %ecx
    rdmsr
    btsl    $_EFER_LME, %eax
    wrmsr

    /* 启用分页 */
    movl    %eax, %cr0

    /* 跳转到64位代码 */
    addq    $(rva(.Lnext_page) - __START_KERNEL_map), %rax
    jmp     *%rax
```

## 5. 页表初始化

### 5.1 早期页表建立

```c
// arch/x86/boot/compressed/pgtable_64.c
void initialize_identity_maps(void *rmode)
{
    unsigned long cmdline;
    struct setup_data *sd;

    /* 解析命令行参数 */
    cmdline = get_cmd_line_ptr();

    /* 检查是否有5级分页支持 */
    if (cmdline_find_option_bool(cmdline, "no5lvl") ||
        cmdline_find_option_bool(cmdline, "disable_5lvl"))
        pgtable_flags &= ~_PAGE_PWT;
    else if (native_cpuid_eax(0x00000007) & (1 << (X86_FEATURE_LA57 & 31)))
        pgtable_flags |= _PAGE_PWT;

    /* 设置5级分页标志 */
    if (pgtable_flags & _PAGE_PWT)
        l5_required = 1;

    /* 设置页表级别 */
    pgtable_l5_enabled = l5_required;

    /* 初始化身份映射 */
    init_identity_mapping();
}
```

### 5.2 页表结构

```c
// arch/x86/boot/compressed/pgtable_64.c
static void init_identity_mapping(void)
{
    unsigned long mappings = 0;

    /* 映射内核代码 */
    if (kernel_size)
        mappings += kernel_size;

    /* 映射引导参数 */
    if (boot_params_ptr)
        mappings += sizeof(struct boot_params);

    /* 映射命令行 */
    if (cmdline_ptr)
        mappings += strlen((char *)cmdline_ptr) + 1;

    /* 创建身份映射 */
    for (unsigned long addr = 0; addr < mappings; addr += PMD_SIZE) {
        ident_map_addr(addr, PMD_SIZE);
    }
}

/* 映射特定地址 */
static void ident_map_addr(unsigned long addr, unsigned long size)
{
    unsigned long end = addr + size;

    /* 4KB映射 */
    while (addr < end) {
        unsigned long next = min(end, (addr + PMD_SIZE) & PMD_MASK);

        /* 检查是否需要映射 */
        if (!ident_map_page(addr))
            return;

        addr = next;
    }
}
```

## 6. 内核初始化

### 6.1 内核主初始化函数

```c
// init/main.c
asmlinkage __visible void __init start_kernel(void)
{
    char *command_line;
    char *after_dashes;

    /* 设置早期参数 */
    set_task_stack_end_magic(&init_task);
    smp_setup_processor_id();
    debug_objects_early_init();

    /* 初始化控制台 */
    console_init();
    if (panic_later)
        panic("Too many boot %s vars at `%s'", panic_later, panic_param);

    /* 锁依赖检查器 */
    lockdep_init();

    /* 调度器初始化 */
    sched_init();

    /* 内存管理初始化 */
    mm_init();

    /* 中断初始化 */
    early_irq_init();
    init_IRQ();

    /* 时间初始化 */
    tick_init();
    init_timers();

    /* 控制台完成初始化 */
    console_init();

    /* 其余子系统初始化 */
    trap_init();
    mm_init();

    /* 进程1初始化 */
    rest_init();
}
```

### 6.2 x86_64特定初始化

```c
// arch/x86/kernel/setup.c
void __init setup_arch(char **cmdline_p)
{
    /* 内存管理初始化 */
    init_mm.start_code = (unsigned long)_text;
    init_mm.end_code = (unsigned long)_etext;
    init_mm.end_data = (unsigned long)_edata;
    init_mm.brk = _brk_end;

    /* 设置命令行 */
    *cmdline_p = boot_command_line;

    /* 内存检测 */
    strlcpy(boot_command_line, boot_command_line, COMMAND_LINE_SIZE);
    *cmdline_p = boot_command_line;

    /* CPU特性检测 */
    early_cpu_init();
    jump_label_init();
    static_call_init();
    early_ioremap_init();

    /* 内存映射初始化 */
    init_mem_mapping();

    /* 内存区域初始化 */
    early_trap_pf_init();
    mmu_cr4_features = __read_cr4();

    /* 内存管理初始化 */
    initmem_init();
    dma_contiguous_reserve(0);

    /* CPU拓扑初始化 */
    init_cpu_features();
    early_platform_device_detection();
    early_acpi_boot_init();
    initmem_rodata();
    reserve_real_mode();
    trim_platform_memory_ranges();
    trim_bios_range();
    early_ioremap_reset();
    setup_real_mode();
    memblock_set_current_limit(get_max_mapped());
    dma_contiguous_reserve(0);
    init_mem_mapping();
    init_trap_init();
    early_cpu_init();
    jump_label_init();
    static_call_init();
    early_ioremap_init();
    trap_init();
    mm_init();
}
```

## 7. 中断和异常初始化

### 7.1 IDT初始化

```c
// arch/x86/kernel/idt.c
void __init idt_setup_apic_and_irq_gates(void)
{
    int i;

    /* 设置CPU特定的异常 */
    for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
        set_intr_gate(i, entry_IDT[i]);

    /* 设置系统向量 */
    for_each_clear_bit_from(i, system_vectors, FIRST_SYSTEM_VECTOR) {
        entry_IDT[i] = __entry_gate[i];
        set_bit(i, system_vectors);
    }

    /* 设置外部中断 */
    for (i = FIRST_EXTERNAL_VECTOR; i < NR_VECTORS; i++)
        set_intr_gate(i, entry_IDT[i]);
}
```

### 7.2 中断控制器初始化

```c
// arch/x86/kernel/apic/apic.c
void __init init_IRQ(void)
{
    int i;

    /* 初始化中断描述符表 */
    x86_init.irqs.intr_init();

    /* 初始化本地APIC */
    x86_init.irqs.pre_vector_init();

    /* 设置中断栈 */
    for (i = 0; i < NR_VECTORS; i++)
        set_intr_gate(i, interrupt[i]);

    /* 初始化中断控制器 */
    x86_init.irqs.trap_init();

    /* 设置系统调用门 */
    set_system_intr_gate(IA32_SYSCALL_VECTOR, entry_INT80_32);
}
```

## 8. 实际启动流程示例

### 8.1 完整启动序列

```c
// 启动流程示例
static void __init x86_64_start_kernel(void)
{
    /* 设置IDT */
    load_idt((const struct desc_ptr *)&idt_descr);

    /* 初始化GDT */
    load_gdt(&early_gdt_descr);

    /* 设置段寄存器 */
    asm volatile("movl %0,%%ds" :: "r" (__KERNEL_DS) : "memory");
    asm volatile("movl %0,%%es" :: "r" (__KERNEL_DS) : "memory");
    asm volatile("movl %0,%%ss" :: "r" (__KERNEL_DS) : "memory");

    /* 初始化栈 */
    asm volatile("movq %0,%%rsp" :: "r" (init_thread_union + THREAD_SIZE - 16) : "memory");

    /* 清除BSS */
    memset(__bss_start, 0, __bss_stop - __bss_start);

    /* 调用内核主函数 */
    x86_64_start_reservations(real_mode_data);
}
```

### 8.2 早期调试输出

```c
// 早期调试支持
static void early_printk(const char *str)
{
    while (*str) {
        if (*str == '\n') {
            early_serial_putchar('\r');
        }
        early_serial_putchar(*str);
        str++;
    }
}

/* 串口初始化 */
static void early_serial_init(void)
{
    /* 设置波特率 */
    outb(0x83, UART_LCR);    /* DLAB = 1 */
    outb(0x01, UART_DLL);    /* 115200 baud */
    outb(0x00, UART_DLM);
    outb(0x03, UART_LCR);    /* 8N1 */

    /* 启用FIFO */
    outb(0x01, UART_FCR);    /* 启用FIFO */

    /* 启用发送 */
    outb(0x0b, UART_MCR);    /* DTR, RTS, OUT2 */
}
```

## 9. 启动参数处理

### 9.1 命令行参数解析

```c
// init/main.c
static int __init do_early_param(char *param, char *val,
                                 const char *unused, void *arg)
{
    const struct obs_kernel_param *p;

    for (p = __setup_start; p < __setup_end; p++) {
        if ((p->early && parameq(param, p->str)) ||
            (strcmp(param, "console") == 0 &&
             strcmp(p->str, "earlycon") == 0)) {
            if (p->setup_func(val) != 0)
                pr_warn("Malformed early option '%s'\n", param);
        }
    }

    /* 我们已经处理了所有的早期参数 */
    return 0;
}

/* 处理命令行参数 */
static void __init parse_early_options(void)
{
    parse_args("early options", boot_command_line, NULL, 0, 0, 0, NULL,
               do_early_param);
}
```

### 9.2 内核参数处理

```c
// kernel/params.c
/* 内核参数处理 */
int parse_args(const char *doing,
               char *args,
               const char *param_start,
               unsigned int num,
               s16 min_level,
               u16 max_level,
               void *arg,
               int (*unknown)(char *param, char *val,
                              const char *doing, void *arg))
{
    char *param, *val;
    int ret;

    args = skip_spaces(args);

    while (*args) {
        int err;
        int argc = 0;

        /* 提取参数 */
        ret = parse_one_param(args, param_start, num, min_level,
                             max_level, arg, unknown, &param, &val);
        if (ret < 0)
            return ret;

        /* 处理参数 */
        err = handle_param(param, val, doing, arg);
        if (err < 0)
            return err;

        args = next_arg(args, NULL);
    }

    return 0;
}
```

## 10. 启动调试和故障排除

### 10.1 早期调试信息

```c
// 启动调试信息输出
static void __init show_kernel_info(void)
{
    printk(KERN_INFO "Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
           LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n");

    printk(KERN_INFO "Command line: %s\n", boot_command_line);

    printk(KERN_INFO "x86/fpu: xstate_offset[%x], xstate_sizes[%x]\n",
           fpu_kernel_xstate.offset, fpu_kernel_xstate.size);

    printk(KERN_INFO "BIOS-provided physical RAM map:\n");
    print_memory_map();
}
```

### 10.2 启动失败诊断

```c
// 启动失败处理
void __init x86_64_start_reservations(char *real_mode_data)
{
    /* 检查启动参数 */
    if (!boot_params.hdr.version) {
        /* 启动参数无效 */
        early_printk("Boot params invalid\n");
        for (;;)
            cpu_relax();
    }

    /* 检查内核加载地址 */
    if (boot_params.hdr.code32_start < __START_KERNEL_map) {
        early_printk("Kernel loaded too low\n");
        for (;;)
            cpu_relax();
    }

    /* 继续初始化 */
    x86_64_start_kernel(real_mode_data);
}
```

## 11. 总结

x86_64架构的启动过程展现了现代操作系统的复杂性：

1. **多阶段启动**：从16位实模式到64位长模式的逐步转换
2. **硬件抽象**：通过GDT、IDT等机制实现硬件抽象
3. **内存管理**：早期页表建立和身份映射
4. **中断处理**：IDT初始化和中断控制器配置
5. **参数处理**：命令行参数和内核参数解析

理解启动过程对于内核开发、系统调试和性能优化都具有重要意义。

---

*本分析基于Linux 6.17内核源代码，涵盖了x86_64架构启动过程的完整实现。*