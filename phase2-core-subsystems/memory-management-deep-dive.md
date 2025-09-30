# Linux内核内存管理子系统深度解析

## 1. 内存管理概述

Linux内存管理是操作系统最复杂的子系统之一，负责虚拟内存管理、物理页分配、地址转换和内存映射等核心功能。Linux采用分页机制实现虚拟内存，为每个进程提供独立的地址空间。

### 1.1 虚拟内存与物理内存

```c
/* 内存管理核心概念 */
/* 每个进程都有独立的虚拟地址空间 */
struct mm_struct {
    struct vm_area_struct *mmap;    /* 虚拟内存区域链表 */
    struct rb_root mm_rb;          /* 红黑树组织的VMA */
    struct vm_area_struct *mmap_cache; /* 最近使用的VMA缓存 */
    unsigned long (*get_unmapped_area) (struct file *filp,
                unsigned long addr, unsigned long len,
                unsigned long pgoff, unsigned long flags);
    void (*unmap_area) (struct mm_struct *mm, unsigned long addr);

    /* 内存区域统计 */
    unsigned long total_vm;        /* 总页面数 */
    unsigned long locked_vm;       /* 锁定页面数 */
    unsigned long pinned_vm;       /* 固定页面数 */
    unsigned long data_vm;         /* 数据段页面数 */
    unsigned long exec_vm;         /* 代码段页面数 */
    unsigned long stack_vm;        /* 栈段页面数 */

    /* 代码段和数据段 */
    unsigned long start_code, end_code, start_data, end_data;
    unsigned long start_brk, brk, start_stack;

    /* 参数和环境变量 */
    unsigned long arg_start, arg_end, env_start, env_end;

    /* 页表管理 */
    pgd_t * pgd;                   /* 页全局目录 */
    atomic_t mm_users;             /* 用户空间计数 */
    atomic_t mm_count;             /* 内核空间计数 */

    /* 内存描述符链表 */
    struct list_head mmlist;       /* 所有mm_struct的链表 */

    /* 信号量 */
    struct rw_semaphore mmap_sem;

    /* 内存映射操作 */
    spinlock_t page_table_lock;    /* 页表锁 */
    struct list_head mmlist;       /* 内存管理链表 */

    /* ... 更多字段 */
};
```

### 1.2 地址空间布局

```c
/* x86_64架构的地址空间布局 */
#define TASK_SIZE_MAX      ((1UL << 47) - PAGE_SIZE)
#define DEFAULT_MAP_WINDOW ((1UL << 47) - PAGE_SIZE)
#define STACK_TOP_MAX      TASK_SIZE_MAX

/* 用户空间布局 */
#define PAGE_OFFSET         ((unsigned long)__PAGE_OFFSET)
#define VMALLOC_START       (PAGE_OFFSET)
#define VMALLOC_END         (VMALLOC_START + (1UL << 30))
#define MODULES_VADDR       (VMALLOC_END - (1UL << 30))
#define MODULES_END         (VMALLOC_END)
#define FIXADDR_START       (MODULES_END - PAGE_SIZE)
#define FIXADDR_END         (FIXADDR_START + PAGE_SIZE)

/* 内核空间布局 */
#define __PAGE_OFFSET       ACPI_PADDR
#define PAGE_OFFSET         ((unsigned long)__PAGE_OFFSET)
#define VMEMMAP_START       (PAGE_OFFSET + (1UL << 40))
#define VMEMMAP_END         (VMEMMAP_START + (1UL << 40))
```

## 2. 页表管理机制

### 2.1 多级页表结构

```c
/* x86_64四级页表结构 */
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { p4dval_t p4d; } p4d_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pteval_t pte; } pte_t;

/* 页表项定义 */
#define _PAGE_PRESENT   0x001    /* 页存在 */
#define _PAGE_RW       0x002    /* 可读写 */
#define _PAGE_USER     0x004    /* 用户空间可访问 */
#define _PAGE_PWT      0x008    /* 写透缓存 */
#define _PAGE_PCD      0x010    /* 禁用缓存 */
#define _PAGE_ACCESSED 0x020    /* 已访问 */
#define _PAGE_DIRTY    0x040    /* 已修改 */
#define _PAGE_PSE      0x080    /* 页大小扩展 */
#define _PAGE_GLOBAL   0x100    /* 全局页 */
#define _PAGE_NX       0x8000000000000000 /* 不可执行 */

/* 页表操作宏 */
#define pgd_index(addr) (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pud_index(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr) (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
```

### 2.2 页表创建和映射

```c
/* 创建页表 */
static int __alloc_pte(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
    pte_t *pte = pte_alloc_map(mm, pmd, address);
    if (!pte)
        return -ENOMEM;

    /* 初始化页表项 */
    set_pte_at(mm, address, pte, pte_mkdirty(*pte));
    return 0;
}

/* 设置页表项 */
static inline void set_pte_at(struct mm_struct *mm, unsigned long addr,
               pte_t *ptep, pte_t pteval)
{
    if (sizeof(pteval_t) > sizeof(unsigned long))
        set_pte_at(mm, addr, ptep, pteval);
    else
        native_set_pte(ptep, pteval);
}

/* 地址转换函数 */
static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
    unsigned long y = x - __START_KERNEL_map;

    /* 检查是否在内核地址空间 */
    if (y >= KERNEL_IMAGE_SIZE)
        return x;

    return y + phys_base;
}

/* 虚拟地址到物理地址转换 */
unsigned long virt_to_phys(volatile void *address)
{
    return __phys_addr_nodebug((unsigned long)address);
}
```

## 3. 物理页管理

### 3.1 伙伴系统

```c
/* 页面描述符 */
struct page {
    unsigned long flags;          /* 页面标志 */
    atomic_t _count;              /* 引用计数 */
    atomic_t _mapcount;           /* 映射计数 */
    unsigned long private;        /* 私有数据 */
    struct address_space *mapping;/* 地址空间 */
    pgoff_t index;                /* 页面索引 */
    struct list_head lru;         /* LRU链表 */

    union {
        struct {
            unsigned long inuse;  /* 使用中的对象数 */
            struct kmem_cache *slab_cache; /* Slab缓存 */
            union {
                struct slab *slab_page;   /* Slab页面 */
                struct {
                    struct list_head slab_list; /* Slab链表 */
                    void *freelist;         /* 空闲对象列表 */
                    void *s_mem;            /* 对象内存区域 */
                };
            };
        };

        struct { /* 用于伙伴系统 */
            struct list_head buddy_list; /* 伙伴链表 */
            unsigned int order;         /* 页块大小 */
        };

        struct { /* 用于私有页映射 */
            spinlock_t ptl;
            struct page *first_page;    /* 复合页的第一页 */
        };
    };

    /* ... 更多字段 */
};

/* 伙伴系统管理结构 */
struct zone {
    /* 页面统计 */
    unsigned long free_pages;      /* 空闲页面数 */
    unsigned long min_pages;       /* 最小页面数 */
    unsigned long lowmem_reserve[MAX_NR_ZONES]; /* 低内存保留 */

    /* 伙伴系统 */
    struct free_area free_area[MAX_ORDER]; /* 空闲区域数组 */

    /* 页面回收 */
    unsigned long pages_scanned;   /* 扫描的页面数 */
    spinlock_t lock;               /* 区域锁 */

    /* 等待队列 */
    wait_queue_head_t wait_table;  /* 等待表 */
    unsigned long wait_table_hash_nr_entries;
    unsigned long wait_table_bits;

    /* 内存策略 */
    struct zone_padding _pad1_;

    /* 统计信息 */
    atomic_t vm_stat[NR_VM_ZONE_STAT_ITEMS];

    /* 内存不足处理 */
    unsigned long percpu_drift_mark;

    /* ... 更多字段 */
};

/* 空闲区域 */
struct free_area {
    struct list_head free_list[MIGRATE_TYPES]; /* 空闲页链表 */
    unsigned long nr_free;          /* 空闲页数 */
};
```

### 3.2 页面分配和释放

```c
/* 分配单个页面 */
struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
{
    return alloc_pages_current(gfp_mask, order);
}

/* 通用页面分配 */
struct page *__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
                   int preferred_nid, nodemask_t *nodemask)
{
    struct page *page;

    /* 快速路径：从当前区域分配 */
    page = get_page_from_freelist(gfp_mask, order, alloc_flags,
                     preferred_nid, nodemask);
    if (likely(page))
        return page;

    /* 慢速路径：内存回收和重新分配 */
    page = __alloc_pages_slowpath(gfp_mask, order, nodemask);
    if (!page)
        return NULL;

    return page;
}

/* 释放页面 */
void __free_pages(struct page *page, unsigned int order)
{
    if (put_page_testzero(page)) {
        if (order == 0)
            free_hot_cold_page(page, false);
        else
            __free_pages_ok(page, order);
    }
}

/* 伙伴系统释放 */
static inline void __free_one_page(struct page *page,
                   unsigned long pfn,
                   struct zone *zone, unsigned int order,
                   int migratetype)
{
    unsigned long page_idx;
    unsigned long combined_idx;
    unsigned long buddy_idx;
    struct page *buddy;

    /* 计算页面索引 */
    page_idx = pfn & ((1 << MAX_ORDER) - 1);

    /* 尝试与伙伴合并 */
    while (order < MAX_ORDER - 1) {
        buddy_idx = __find_buddy_index(page_idx, order);
        buddy = page + (buddy_idx - page_idx);

        /* 检查是否可以合并 */
        if (!page_is_buddy(page, buddy, order))
            break;

        /* 从空闲链表移除伙伴 */
        list_del(&buddy->lru);
        zone->free_area[order].nr_free--;

        /* 合并页面 */
        combined_idx = buddy_idx & page_idx;
        page = page + (combined_idx - page_idx);
        page_idx = combined_idx;
        order++;
    }

    /* 添加到空闲链表 */
    set_page_order(page, order);
    list_add(&page->lru, &zone->free_area[order].free_list[migratetype]);
    zone->free_area[order].nr_free++;
}
```

## 4. Slab分配器

### 4.1 Slab缓存结构

```c
/* Slab缓存描述符 */
struct kmem_cache {
    /* 缓存属性 */
    unsigned int batchcount;       /* 批量分配数量 */
    unsigned int limit;            /* 限制 */
    unsigned int shared;           /* 共享 */
    unsigned int size;             /* 对象大小 */
    unsigned int align;            /* 对齐 */

    /* 对象管理 */
    slab_flags_t flags;            /* 标志 */
    unsigned int num;              /* 每个slab的对象数 */

    /* Slab管理 */
    struct list_head slabs_full;   /* 满slab链表 */
    struct list_head slabs_partial;/* 部分满slab链表 */
    struct list_head slabs_free;   /* 空slab链表 */

    /* 统计信息 */
    unsigned long gfporder;        /* 分配的页面阶数 */
    unsigned int colour_off;       /* 颜色偏移 */
    struct kmem_cache_node *node[MAX_NUMNODES]; /* 节点管理 */

    /* 对象构造和析构 */
    void (*ctor)(void *obj);      /* 构造函数 */
    void (*dtor)(void *obj);      /* 析构函数 */

    /* 缓存名称 */
    const char *name;             /* 缓存名称 */
    struct list_head list;         /* 缓存链表 */

    /* 调试信息 */
    int refcount;                 /* 引用计数 */
    int object_size;              /* 对象实际大小 */
    int inuse;                    /* 使用中的对象数 */
    int align;                    /* 对齐要求 */

    /* ... 更多字段 */
};

/* Slab描述符 */
struct slab {
    struct list_head list;        /* Slab链表 */
    unsigned long colouroff;      /* 颜色偏移 */
    void *s_mem;                  /* 对象内存 */
    void *freelist;               /* 空闲对象列表 */
    unsigned int inuse;           /* 使用中的对象数 */
    kmem_bufctl_t free;           /* 空闲对象索引 */
    unsigned short nodeid;         /* 节点ID */
};
```

### 4.2 Slab对象分配

```c
/* 从slab缓存分配对象 */
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
    void *objp;

    /* 检查是否需要重新填充 */
    if (unlikely(!cachep->node[numa_node_id()])) {
        objp = cache_alloc_refill(cachep, flags);
        if (!objp)
            return NULL;
        return objp;
    }

    /* 从本地CPU缓存分配 */
    objp = ____cache_alloc(cachep, flags);
    if (likely(objp))
        return objp;

    /* 重新分配 */
    return cache_alloc_refill(cachep, flags);
}

/* 重新填充slab */
static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
    int batchcount;
    struct kmem_cache_node *n;
    struct list_head *entry;
    struct slab *slabp;

    /* 获取节点管理结构 */
    n = cachep->node[numa_node_id()];

    /* 检查部分满slab链表 */
    if (!list_empty(&n->slabs_partial)) {
        entry = n->slabs_partial.next;
        slabp = list_entry(entry, struct slab, list);

        /* 从slab分配对象 */
        return cache_alloc_refill_one(cachep, n, slabp, flags);
    }

    /* 检查空slab链表 */
    if (!list_empty(&n->slabs_free)) {
        entry = n->slabs_free.next;
        slabp = list_entry(entry, struct slab, list);

        /* 分配对象并移动到部分满链表 */
        list_move(&slabp->list, &n->slabs_partial);
        return cache_alloc_refill_one(cachep, n, slabp, flags);
    }

    /* 分配新的slab */
    slabp = cache_grow(cachep, flags, numa_node_id());
    if (!slabp)
        return NULL;

    /* 从新slab分配对象 */
    return cache_alloc_refill_one(cachep, n, slabp, flags);
}

/* 释放对象到slab */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
    unsigned long flags;

    /* 检查对象是否有效 */
    if (unlikely(!cachep || !objp))
        return;

    /* 获取slab描述符 */
    local_irq_save(flags);
    debug_check_no_locks_freed(objp, cachep->object_size);

    /* 释放对象 */
    ____cache_free(cachep, objp);

    local_irq_restore(flags);
}
```

## 5. 内存映射和mmap

### 5.1 内存区域管理

```c
/* 虚拟内存区域描述符 */
struct vm_area_struct {
    /* 区域属性 */
    unsigned long vm_start;       /* 起始地址 */
    unsigned long vm_end;         /* 结束地址 */
    struct vm_area_struct *vm_next; /* 下一个区域 */
    pgprot_t vm_page_prot;        /* 页面保护 */

    /* 区域标志 */
    unsigned long vm_flags;        /* 标志位 */

    /* 红黑树节点 */
    struct rb_node vm_rb;         /* 红黑树节点 */

    /* 操作函数 */
    const struct vm_operations_struct *vm_ops; /* 操作函数 */
    unsigned long vm_pgoff;       /* 页面偏移 */
    struct file * vm_file;        /* 关联文件 */
    void * vm_private_data;       /* 私有数据 */

    /* 优先级 */
    int vm_userfaultfd_ctx;       /* 用户faultfd上下文 */
};

/* 内存区域操作 */
struct vm_operations_struct {
    void (*open)(struct vm_area_struct * area);
    void (*close)(struct vm_area_struct * area);
    int (*fault)(struct vm_fault *vmf);
    int (*page_mkwrite)(struct vm_fault *vmf);
    int (*access)(struct vm_area_struct *vma, unsigned long addr,
              void *buf, int len, int write);

    /* 通知操作 */
    const char *(*name)(struct vm_area_struct *vma);
    int (*set_policy)(struct vm_area_struct *vma,
              struct mempolicy *new);
    struct mempolicy *(*get_policy)(struct vm_area_struct *vma,
                    unsigned long addr);
    int (*migrate)(struct vm_area_struct *vma, const nodemask_t *from,
            const nodemask_t *to, unsigned long flags);
};

/* 内存区域标志 */
#define VM_READ       0x00000001  /* 可读 */
#define VM_WRITE      0x00000002  /* 可写 */
#define VM_EXEC       0x00000004  /* 可执行 */
#define VM_SHARED     0x00000008  /* 共享 */
#define VM_MAYREAD    0x00000010  /* 可能可读 */
#define VM_MAYWRITE   0x00000020  /* 可能可写 */
#define VM_MAYEXEC    0x00000040  /* 可能可执行 */
#define VM_MAYSHARE   0x00000080  /* 可能共享 */
#define VM_GROWSDOWN  0x00000100  /* 可向下生长 */
#define VM_GROWSUP    0x00000200  /* 可向上生长 */
```

### 5.2 mmap系统调用实现

```c
/* mmap系统调用 */
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
        unsigned long, prot, unsigned long, flags,
        unsigned long, fd, unsigned long, off)
{
    long error;
    struct file *file;

    /* 检查参数 */
    error = -EINVAL;
    if (off & ~PAGE_MASK)
        goto out;

    /* 获取文件 */
    if (flags & MAP_SHARED) {
        error = -EBADF;
        if (!(flags & MAP_ANONYMOUS)) {
            file = fget(fd);
            if (!file)
                goto out;
        }
    }

    /* 调用mmap实现 */
    error = sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);

    if (file)
        fput(file);

out:
    return error;
}

/* mmap核心实现 */
unsigned long do_mmap(struct file *file, unsigned long addr,
              unsigned long len, unsigned long prot,
              unsigned long flags, unsigned long pgoff,
              unsigned long *populate)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    unsigned long addr;
    int error = -ENOMEM;

    /* 检查参数 */
    if (len == 0)
        return -EINVAL;

    /* 对齐长度 */
    len = PAGE_ALIGN(len);

    /* 检查地址范围 */
    if (!len)
        return addr;

    /* 检查保护位 */
    if (!(prot & (PROT_READ | PROT_WRITE | PROT_EXEC)))
        return -EINVAL;

    /* 获取未映射区域 */
    addr = get_unmapped_area(file, addr, len, pgoff, flags);
    if (addr & ~PAGE_MASK)
        return addr;

    /* 创建虚拟内存区域 */
    vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
    if (!vma)
        return -ENOMEM;

    /* 初始化VMA */
    INIT_LIST_HEAD(&vma->anon_vma_chain);
    vma->vm_mm = mm;
    vma->vm_start = addr;
    vma->vm_end = addr + len;
    vma->vm_flags = vm_flags;
    vma->vm_page_prot = vm_get_page_prot(vm_flags);
    vma->vm_pgoff = pgoff;

    /* 设置文件映射 */
    if (file) {
        vma->vm_file = get_file(file);
        error = mmap_region(file, vma, vm_flags, addr);
        if (error)
            goto free_vma;
    }

    /* 添加到内存描述符 */
    vma_link(mm, vma, prev, rb_link, rb_parent);

    /* 更新统计 */
    mm->total_vm += len >> PAGE_SHIFT;
    vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);

    return addr;

free_vma:
    kmem_cache_free(vm_area_cachep, vma);
    return error;
}
```

## 6. 缺页异常处理

### 6.1 缺页异常流程

```c
/* 缺页异常处理 */
static noinline int __do_page_fault(struct pt_regs *regs,
                   unsigned long error_code,
                   unsigned long address)
{
    struct vm_area_struct *vma;
    struct task_struct *tsk;
    struct mm_struct *mm;
    int fault;

    tsk = current;
    mm = tsk->mm;

    /* 检查地址是否在用户空间 */
    if (unlikely(fault_in_kernel_space(address))) {
        if (!(error_code & (X86_PF_USER | X86_PF_INSTR)))
            return vmalloc_fault(address);
        /* 内核空间错误 */
        return -1;
    }

    /* 获取内存信号量 */
    if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
        if (!(error_code & X86_PF_USER) &&
            !search_exception_tables(regs->ip)) {
            bad_area_nosemaphore(regs, error_code, address);
            return -1;
        }
retry:
        down_read(&mm->mmap_sem);
    } else {
        might_sleep();
    }

    /* 查找VMA */
    vma = find_vma(mm, address);
    if (unlikely(!vma)) {
        bad_area(regs, error_code, address);
        return -1;
    }

    /* 检查VMA是否包含地址 */
    if (likely(vma->vm_start <= address))
        goto good_area;

    /* 检查栈扩展 */
    if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
        bad_area(regs, error_code, address);
        return -1;
    }

    /* 检查地址是否合理 */
    if (unlikely(expand_stack(vma, address))) {
        bad_area(regs, error_code, address);
        return -1;
    }

good_area:
    /* 检查访问权限 */
    if (unlikely(error_code & (X86_PF_PROT | X86_PF_WRITE))) {
        if (unlikely(!(vma->vm_flags & VM_WRITE))) {
            bad_area(regs, error_code, address);
            return -1;
        }
    } else {
        if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC)))) {
            bad_area(regs, error_code, address);
            return -1;
        }
    }

    /* 处理缺页异常 */
    fault = handle_mm_fault(mm, vma, address, flags);

    /* 检查处理结果 */
    if (unlikely(fault & VM_FAULT_ERROR)) {
        if (fault & VM_FAULT_OOM)
            goto out_of_memory;
        else if (fault & VM_FAULT_SIGBUS)
            goto do_sigbus;
        BUG();
    }

    /* 成功处理 */
    up_read(&mm->mmap_sem);
    return 0;

out_of_memory:
    up_read(&mm->mmap_sem);
    if (!user_mode(regs)) {
        /* 内核OOM */
        no_context(regs, error_code, address, SIGKILL, 0);
        return -1;
    }

    /* 用户空间OOM */
    pagefault_out_of_memory();
    return -1;

do_sigbus:
    up_read(&mm->mmap_sem);

    /* SIGBUS信号 */
    tsk->thread.cr2 = address;
    tsk->thread.error_code = error_code;
    tsk->thread.trap_nr = X86_TRAP_PF;

    force_sig_info(SIGBUS, &info, tsk);
    return -1;
}
```

### 6.2 页面故障处理

```c
/* 处理内存管理故障 */
int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
             unsigned long address, unsigned int flags)
{
    int ret;

    /* 检查是否需要锁定 */
    if (flags & FAULT_FLAG_USER)
        mem_cgroup_oom_enable();

    /* 处理匿名映射 */
    if (!(vma->vm_flags & VM_SHARED))
        ret = do_anonymous_page(mm, vma, address, pmd, flags);
    else
        ret = do_shared_page(mm, vma, address, pmd, flags);

    /* 检查结果 */
    if (flags & FAULT_FLAG_USER)
        mem_cgroup_oom_disable();

    return ret;
}

/* 处理匿名页面 */
static int do_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pmd_t *pmd,
                unsigned int flags)
{
    struct page *page;
    spinlock_t *ptl;
    pte_t *pte;

    /* 分配页面 */
    page = alloc_zeroed_user_highpage_movable(vma, address);
    if (!page)
        return VM_FAULT_OOM;

    /* 获取页表锁 */
    pte = get_locked_pte(mm, address, &ptl);
    if (!pte)
        return VM_FAULT_OOM;

    /* 检查是否已经有映射 */
    if (!pte_none(*pte)) {
        /* 释放页面 */
        page_cache_release(page);
        pte_unmap_unlock(pte, ptl);
        return 0;
    }

    /* 设置页表项 */
    inc_mm_counter_fast(mm, MM_ANONPAGES);
    page_add_new_anon_rmap(page, vma, address);
    set_pte_at(mm, address, pte, mk_pte(page, vma->vm_page_prot));

    /* 解锁 */
    pte_unmap_unlock(pte, ptl);
    return 0;
}
```

## 7. 内存回收机制

### 7.1 页面回收策略

```c
/* 页面回收状态 */
struct scan_control {
    /* 扫描参数 */
    unsigned long nr_to_reclaim;  /* 需要回收的页面数 */
    unsigned long nr_scanned;     /* 已扫描的页面数 */
    unsigned long nr_reclaimed;   /* 已回收的页面数 */

    /* 扫描控制 */
    int order;                    /* 分配阶数 */
    gfp_t gfp_mask;              /* GFP标志 */

    /* 优先级 */
    int priority;                /* 回收优先级 */

    /* 统计信息 */
    unsigned long may_writepage;  /* 允许写回 */
    unsigned long may_swap;       /* 允许交换 */
    unsigned long hibernation_mode; /* 休眠模式 */
};

/* 内存区域收缩 */
static int shrink_zone(struct zone *zone, struct scan_control *sc)
{
    unsigned long nr_anon, nr_file, percentage;
    unsigned long nr_to_scan;

    /* 计算扫描比例 */
    percentage = min(unsigned long, current->reclaim_stat.reclaimed_ratio, 100);
    nr_to_scan = zone->nr_scanned * percentage / 100;

    /* 扫描匿名页面 */
    nr_anon = scan_lru_pages(zone, sc, LRU_INACTIVE_ANON, nr_to_scan);
    shrink_active_list(nr_anon, zone, sc, LRU_ACTIVE_ANON, &nr_to_scan);

    /* 扫描文件页面 */
    nr_file = scan_lru_pages(zone, sc, LRU_INACTIVE_FILE, nr_to_scan);
    shrink_active_list(nr_file, zone, sc, LRU_ACTIVE_FILE, &nr_to_scan);

    /* 检查是否需要交换 */
    if (sc->may_swap) {
        shrink_swap_mapping(zone, sc);
    }

    return sc->nr_reclaimed;
}

/* 活跃页面列表收缩 */
static void shrink_active_list(unsigned long nr_to_scan,
                   struct zone *zone, struct scan_control *sc,
                   enum lru_list lru, unsigned long *nr_to_scan)
{
    struct page *page;
    struct list_head *l_hold;
    unsigned long nr_taken = 0;
    int file = is_file_lru(lru);

    /* 暂存页面 */
    l_hold = &zone->lru_hold;

    /* 从LRU列表移动页面 */
    spin_lock_irq(&zone->lru_lock);
    while (!list_empty(&zone->lru[lru].list)) {
        page = list_entry(zone->lru[lru].list.next, struct page, lru);

        /* 检查页面状态 */
        if (unlikely(!page_mapped(page))) {
            list_del(&page->lru);
            list_add(&page->lru, &zone->lru[lru + 1].list);
            continue;
        }

        /* 移动到暂存列表 */
        list_del(&page->lru);
        list_add(&page->lru, l_hold);
        nr_taken++;
    }
    spin_unlock_irq(&zone->lru_lock);

    /* 处理暂存页面 */
    while (!list_empty(l_hold)) {
        page = list_entry(l_hold->next, struct page, lru);
        list_del(&page->lru);

        /* 检查是否应该回收 */
        if (page_referenced(page, 0, sc->target_mem_cgroup,
                   &vm_flags)) {
            /* 被引用的页面移回活跃列表 */
            list_add(&page->lru, &zone->lru[lru].list);
        } else {
            /* 未被引用的页面移到不活跃列表 */
            list_add(&page->lru, &zone->lru[lru + 1].list);
        }
    }
}
```

### 7.2 kswapd守护进程

```c
/* kswapd进程 */
static int kswapd(void *p)
{
    unsigned long order;
    struct zone *zone;
    struct zone *preferred_zone;
    struct task_struct *tsk = current;

    /* 设置进程属性 */
    tsk->flags |= PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD;
    set_freezable();

    /* 主循环 */
    for (;;) {
        /* 检查是否需要冻结 */
        try_to_freeze();

        /* 等待需要回收 */
        prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
        if (!balance_pgdat(pgdat, order, classzone_idx))
            schedule();

        /* 执行内存回收 */
        order = balance_pgdat(pgdat, order, classzone_idx);

        /* 完成回收 */
        finish_wait(&pgdat->kswapd_wait, &wait);
    }

    return 0;
}

/* 平衡内存区域 */
static int balance_pgdat(pg_data_t *pgdat, int order, int classzone_idx)
{
    int i;
    unsigned long nr_free = 0;
    struct scan_control sc = {
        .gfp_mask = GFP_KERNEL,
        .order = order,
        .priority = DEF_PRIORITY,
    };

    /* 计算空闲页面 */
    for (i = 0; i <= classzone_idx; i++) {
        struct zone *zone = pgdat->node_zones + i;
        nr_free += zone_page_state(zone, NR_FREE_PAGES);
    }

    /* 检查是否需要回收 */
    if (nr_free >= zone_pages_high(classzone_idx))
        return 1;

    /* 执行回收 */
    for (i = 0; i < classzone_idx; i++) {
        struct zone *zone = pgdat->node_zones + i;

        /* 收缩区域 */
        shrink_zone(zone, &sc);

        /* 检查是否完成 */
        if (sc.nr_reclaimed >= sc.nr_to_reclaim)
            return 1;
    }

    return 0;
}
```

## 8. 实践示例：内存分配器实现

### 8.1 简单的内存池实现

```c
/* 自定义内存池 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#define POOL_SIZE (1024 * 1024)  /* 1MB内存池 */
#define OBJECT_SIZE 256          /* 对象大小 */
#define NUM_OBJECTS (POOL_SIZE / OBJECT_SIZE)

/* 内存池对象 */
struct mem_pool_obj {
    struct list_head list;
    char data[OBJECT_SIZE];
};

/* 内存池描述符 */
struct mem_pool {
    struct list_head free_list;
    struct list_head used_list;
    void *pool_mem;
    unsigned int num_free;
    unsigned int num_used;
    spinlock_t lock;
};

/* 全局内存池 */
static struct mem_pool global_pool;

/* 初始化内存池 */
static int mem_pool_init(void)
{
    struct mem_pool_obj *obj;
    int i;

    /* 分配内存池 */
    global_pool.pool_mem = vmalloc(POOL_SIZE);
    if (!global_pool.pool_mem) {
        printk(KERN_ERR "MemoryPool: Failed to allocate pool memory\n");
        return -ENOMEM;
    }

    /* 初始化链表 */
    INIT_LIST_HEAD(&global_pool.free_list);
    INIT_LIST_HEAD(&global_pool.used_list);
    global_pool.num_free = 0;
    global_pool.num_used = 0;
    spin_lock_init(&global_pool.lock);

    /* 初始化对象 */
    for (i = 0; i < NUM_OBJECTS; i++) {
        obj = (struct mem_pool_obj *)(global_pool.pool_mem + i * OBJECT_SIZE);
        INIT_LIST_HEAD(&obj->list);
        list_add(&obj->list, &global_pool.free_list);
        global_pool.num_free++;
    }

    printk(KERN_INFO "MemoryPool: Initialized with %d objects\n", NUM_OBJECTS);
    return 0;
}

/* 从内存池分配 */
static void *mem_pool_alloc(void)
{
    struct mem_pool_obj *obj;
    unsigned long flags;

    spin_lock_irqsave(&global_pool.lock, flags);

    /* 检查是否有空闲对象 */
    if (list_empty(&global_pool.free_list)) {
        spin_unlock_irqrestore(&global_pool.lock, flags);
        return NULL;
    }

    /* 从空闲列表获取对象 */
    obj = list_first_entry(&global_pool.free_list, struct mem_pool_obj, list);
    list_del(&obj->list);
    list_add(&obj->list, &global_pool.used_list);

    global_pool.num_free--;
    global_pool.num_used++;

    spin_unlock_irqrestore(&global_pool.lock, flags);

    return obj->data;
}

/* 释放对象到内存池 */
static void mem_pool_free(void *ptr)
{
    struct mem_pool_obj *obj;
    unsigned long flags;

    if (!ptr)
        return;

    /* 计算对象地址 */
    obj = container_of(ptr, struct mem_pool_obj, data);

    spin_lock_irqsave(&global_pool.lock, flags);

    /* 从使用列表移除 */
    list_del(&obj->list);

    /* 添加到空闲列表 */
    list_add(&obj->list, &global_pool.free_list);

    global_pool.num_used--;
    global_pool.num_free++;

    spin_unlock_irqrestore(&global_pool.lock, flags);
}

/* 清理内存池 */
static void mem_pool_cleanup(void)
{
    if (global_pool.pool_mem) {
        vfree(global_pool.pool_mem);
        global_pool.pool_mem = NULL;
    }

    printk(KERN_INFO "MemoryPool: Cleanup completed\n");
}

/* 模块初始化 */
static int __init mem_pool_module_init(void)
{
    printk(KERN_INFO "MemoryPool: Module loaded\n");
    return mem_pool_init();
}

/* 模块退出 */
static void __exit mem_pool_module_exit(void)
{
    mem_pool_cleanup();
    printk(KERN_INFO "MemoryPool: Module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Custom memory pool implementation");
module_init(mem_pool_module_init);
module_exit(mem_pool_module_exit);
```

## 9. 内存管理调试和监控

### 9.1 内存统计接口

```c
/* 内存统计信息 */
/proc/meminfo:
  MemTotal:       16384000 kB
  MemFree:        10240000 kB
  MemAvailable:   12288000 kB
  Buffers:          102400 kB
  Cached:          3072000 kB
  SwapCached:          0 kB
  Active:          2048000 kB
  Inactive:        3072000 kB
  Active(anon):   1024000 kB
  Inactive(anon): 1024000 kB
  Active(file):   1024000 kB
  Inactive(file): 2048000 kB

/* Slab统计 */
/proc/slabinfo:
  # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
  kmem_cache         100        100        256        16           1 : tunables    0    0    0 : slabdata      7     7     0
  kmalloc-256        50         50         256        16           1 : tunables    0    0    0 : slabdata      4     4     0

/* 虚拟内存信息 */
/proc/<pid>/maps:
  00400000-0040b000 r-xp 00000000 08:01 123456    /bin/bash
  0060a000-0060b000 r--p 0000a000 08:01 123456    /bin/bash
  0060b000-0060c000 rw-p 0000b000 08:01 123456    /bin/bash
  7f8d00000000-7f8d0020c000 r-xp 00000000 08:01 789012    /lib/x86_64-linux-gnu/libc-2.27.so
```

### 9.2 内存调试工具

```c
/* 内存泄漏检测 */
static void check_memory_leaks(void)
{
    struct mem_pool_obj *obj;
    unsigned long flags;
    int leaks = 0;

    spin_lock_irqsave(&global_pool.lock, flags);

    /* 检查使用中的对象 */
    list_for_each_entry(obj, &global_pool.used_list, list) {
        printk(KERN_WARNING "MemoryPool: Leaked object at %p\n", obj);
        leaks++;
    }

    spin_unlock_irqrestore(&global_pool.lock, flags);

    if (leaks > 0) {
        printk(KERN_WARNING "MemoryPool: %d memory leaks detected\n", leaks);
    }
}

/* 内存使用统计 */
static void mem_pool_stats(void)
{
    unsigned long flags;

    spin_lock_irqsave(&global_pool.lock, flags);

    printk(KERN_INFO "MemoryPool Stats:\n");
    printk(KERN_INFO "  Free objects: %d\n", global_pool.num_free);
    printk(KERN_INFO "  Used objects: %d\n", global_pool.num_used);
    printk(KERN_INFO "  Total objects: %d\n", global_pool.num_free + global_pool.num_used);
    printk(KERN_INFO "  Memory usage: %lu bytes\n",
           (unsigned long)(global_pool.num_used * OBJECT_SIZE));

    spin_unlock_irqrestore(&global_pool.lock, flags);
}
```

## 10. 性能优化建议

### 10.1 内存分配优化
- 使用合适的内存分配器（slab、slub、slob）
- 避免频繁的小内存分配
- 使用内存池减少分配开销
- 合理设置页表缓存

### 10.2 内存访问优化
- 提高缓存命中率
- 减少页面错误
- 使用大页内存
- 优化内存访问模式

### 10.3 NUMA优化
- 考虑NUMA节点亲和性
- 使用本地内存分配
- 避免跨节点内存访问
- 合理设置内存策略

## 11. 总结

Linux内存管理是一个复杂而精密的系统，通过深入理解虚拟内存管理、物理页分配、Slab分配器和内存回收机制，我们可以更好地掌握操作系统的核心内存管理技术。

**关键要点：**
1. 虚拟内存为每个进程提供独立的地址空间
2. 多级页表实现地址转换
3. 伙伴系统管理物理页分配
4. Slab分配器优化小对象分配
5. 内存回收机制保证系统稳定运行

通过本章的学习，你将具备深入理解Linux内存管理的能力，为进一步的系统开发和优化打下坚实基础。