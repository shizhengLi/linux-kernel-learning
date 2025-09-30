# Linux内核构建系统详细说明

## 目录
1. [Makefile系统工作原理](#makefile系统工作原理)
2. [Kconfig配置系统实现](#kconfig配置系统实现)
3. [内核编译完整流程](#内核编译完整流程)
4. [交叉编译支持](#交叉编译支持)
5. [实际应用示例](#实际应用示例)

## Makefile系统工作原理

### 1. 顶层Makefile结构

Linux内核使用递归Makefile系统，顶层Makefile协调整个构建过程：

```makefile
# Makefile - 顶层Makefile主要部分
VERSION = 5
PATCHLEVEL = 15
SUBLEVEL = 0
EXTRAVERSION = -rc1
NAME = Opossums on Parade

# *DOCUMENTATION*
# To see a list of typical targets execute "make help"
# More info can be located in ./README
# Comments in this file are targeted only to the developer, do not
# expect to learn how to build the kernel reading this file.

# Do not:
# o  use make's built-in rules and variables
#    (this increases performance and avoids hard-to-debug behaviour);
# o  print "Entering directory ...";
MAKEFLAGS += -rR --no-print-directory

# Avoid funny character set dependencies
unexport LC_ALL
LC_COLLATE=C
LC_NUMERIC=C
export LC_COLLATE LC_NUMERIC

# Avoid interference with shell env settings
unexport GREP_OPTIONS

# We are using a recursive build, so we need to do a little thinking
# to get the ordering right.
#
# Most importantly: sub-Makefiles should only ever modify files in
# their own directory. If in some directory we have a dependency on
# a file in another dir (which doesn't happen often, but it's often
# unavoidable when linking the built-in.o targets which finally
# turn into vmlinux), we will call a sub make in that other dir, and
# after that we are sure that everything which is needed in that dir is
# built up to date.
#
# The only cases where we need to modify files which have global
# effects are thus separated out and done before the recursive
# building is started.

# To put more focus on warnings, be less verbose as default
# Use 'make V=1' to see the full commands

ifdef V
  ifeq ("$(origin V)", "command line")
    KBUILD_VERBOSE = $(V)
  endif
endif
ifndef KBUILD_VERBOSE
  KBUILD_VERBOSE = 0
endif

ifeq ($(KBUILD_VERBOSE),1)
  quiet =
  Q =
else
  quiet=quiet_
  Q = @
endif

# If the user is running make -s (silent mode), suppress echoing of
# commands

ifneq ($(findstring s,$(filter-out --%,$(MAKEFLAGS))),)
  quiet=silent_
  tools_silent=s
endif

export quiet Q KBUILD_VERBOSE

# kbuild supports saving output files in a separate directory.
# To locate output files in a separate directory two syntaxes are supported.
# In both cases the working directory must be the root of the kernel src.
# 1) O=
# Use "make O=dir/to/store/output/files/"
#
# 2) Set KBUILD_OUTPUT
# Set the environment variable KBUILD_OUTPUT to point to the directory
# where the output files shall be placed.
# export KBUILD_OUTPUT=dir/to/store/output/files/
# make
#
# The O= assignment takes precedence over the KBUILD_OUTPUT environment
# variable.

# KBUILD_SRC is set on invocation of make in OBJ directory
# KBUILD_SRC is not intended to be used by the user
ifeq ($(KBUILD_SRC),)

# OK, Make called in directory where kernel src resides
# Do we want to locate output files in a separate directory?
ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT := $(O)
endif

ifeq ("$(origin O)", "environment")
  KBUILD_OUTPUT := $(O)
endif

# That's our default target when none is given on the command line
PHONY := _all
_all:

# Cancel implicit rules on top Makefile
$(CURDIR)/Makefile Makefile: ;

ifneq ($(KBUILD_OUTPUT),)
# Invoke a second make in the output directory, passing relevant variables
# check that the output directory actually exists
saved-output := $(KBUILD_OUTPUT)
KBUILD_OUTPUT := $(shell cd $(KBUILD_OUTPUT) && /bin/pwd)
$(if $(KBUILD_OUTPUT),, \
     $(error output directory "$(saved-output)" does not exist))

PHONY += $(MAKECMDGOALS) sub-make

$(filter-out _all sub-make $(CURDIR)/Makefile, $(MAKECMDGOALS)) _all: sub-make
    @:

sub-make: FORCE
    $(Q)$(MAKE) -C $(KBUILD_OUTPUT) KBUILD_SRC=$(CURDIR) \
    -f $(CURDIR)/Makefile $(filter-out _all sub-make,$(MAKECMDGOALS))

# Leave processing to above invocation of make
skip-makefile := 1
endif # ifneq ($(KBUILD_OUTPUT),)
endif # ifeq ($(KBUILD_SRC),)

# We process the rest of the Makefile if this is the final invocation of make
ifeq ($(skip-makefile),)

# Do not print "Entering directory ...",
# but we want to display it when entering the output directory
# if that directory is not the current directory
ifeq ("$(origin M)", "command line")
  KBUILD_EXTMOD := $(M)
endif

ifeq ("$(origin W)", "command line")
  export KBUILD_ENABLE_EXTRA_GCC_CHECKS := 1
endif

ifeq ("$(origin W)", "command line")
  export KBUILD_EXTRA_WARN := 1
endif

# To make sure we do not include .config for any of the *config targets
# catch them early, and hand them over to scripts/kconfig/Makefile
# It is allowed to specify more targets when calling make, including
# mixing *config targets and build targets.
# For example 'make oldconfig all'.
# Detect when mixed targets is specified, and make a second invocation
# of make so .config is not included in this case either (for *config).

version_h := include/generated/uapi/linux/version.h

no-dot-config-targets := clean mrproper distclean \
             cscope gtags TAGS tags help% %docs check% coccicheck \
             $(version_h) headers_% archheaders archscripts \
             kernelversion %src-pkg

config-targets := 0
mixed-targets  := 0
dot-config     := 1

ifneq ($(filter $(no-dot-config-targets), $(MAKECMDGOALS)),)
  ifeq ($(filter-out $(no-dot-config-targets), $(MAKECMDGOALS)),)
    dot-config := 0
  endif
endif

ifeq ($(KBUILD_EXTMOD),)
  ifneq ($(filter config %config,$(MAKECMDGOALS)),)
    config-targets := 1
    ifneq ($(filter-out config %config,$(MAKECMDGOALS)),)
      mixed-targets := 1
    endif
  endif
endif

ifeq ($(mixed-targets),1)
# ===========================================================================
# We're called with mixed targets (*config and build targets).
# Handle them one by one.

PHONY += $(MAKECMDGOALS) __build_one_by_one

$(MAKECMDGOALS): __build_one_by_one
    @:

__build_one_by_one:
    $(Q)set -e; \
    for i in $(MAKECMDGOALS); do \
        $(MAKE) -f $(srctree)/Makefile $$i; \
    done

else
ifeq ($(config-targets),1)
# ===========================================================================
# *config targets only - make sure prerequisites are updated, and descend
# in scripts/kconfig to make the *config target

%config: scripts_basic outputmakefile FORCE
    $(Q)$(MAKE) $(build)=scripts/kconfig $@

config: scripts_basic outputmakefile FORCE
    $(Q)$(MAKE) $(build)=scripts/kconfig $@

else
# ===========================================================================
# Build targets only - this includes vmlinux, arch specific targets, clean
# targets and others. In general all targets except *config targets.

ifeq ($(dot-config),1)
# Read in config
-include include/config/auto.conf

# Read in dependencies to all Kconfig* files, make sure to run
# oldconfig if changes are detected.
-include include/config/auto.conf.cmd

# To avoid any implicit rule to kick in, define an empty command
$(KCONFIG_CONFIG) include/config/auto.conf.cmd: ;

# If .config is newer than include/config/auto.conf, someone tinkered
# with it and forgot to run make oldconfig.
# if auto.conf.cmd is missing then we are probably in a cleaned tree so
# we execute the config step to be sure to catch updated Kconfig files
include/config/%.conf: $(KCONFIG_CONFIG) include/config/auto.conf.cmd
    $(Q)$(MAKE) -f $(srctree)/Makefile silentoldconfig

# Allow people to just run `make` as before and not force them to configure
PHONY += all
_all:

# The all: target is the default when no target is given on the
# command line.
# This allow a user to issue only `make` to build a kernel including modules
# Defaults to vmlinux, but the arch makefile usually adds further targets
all: vmlinux

# Core target
# vmlinux is the main kernel target
vmlinux: scripts/link-vmlinux.sh autoksyms_recursive $(vmlinux-deps)
    +$(call if_changed,link-vmlinux)

# Build modules
modules: $(vmlinux-dirs)
    $(Q)$(MAKE) $(build)=$(build-dir) $(build-target)

# Target to prepare building external modules
PHONY += modules_prepare
modules_prepare: prepare scripts

# Target to install modules
PHONY += modules_install
modules_install: _modinst_ _modinst_post

PHONY += _modinst_
_modinst_:
    @rm -rf $(MODLIB)/kernel
    @rm -f $(MODLIB)/source
    @mkdir -p $(MODLIB)/kernel
    @ln -s $(srctree) $(MODLIB)/source
    @if [ ! $(objtree) -ef $(srctree) ]; then \
        rm -f $(MODLIB)/build; \
        ln -s $(objtree) $(MODLIB)/build; \
    fi
    @cp -f modules.builtin $(MODLIB)/
    $(Q)$(MAKE) -f $(srctree)/scripts/Makefile.modinst

# Clean targets
clean: rm-files := $(CLEAN_FILES)
clean-dirs := $(addprefix _clean_, . $(vmlinux-alldirs))

PHONY += clean
clean: $(clean-dirs)
    $(call cmd,rmfiles)
    @find . $(RCS_FIND_IGNORE) \
        \( -name '*.[oas]' -o -name '*.ko' -o -name '.*.cmd' \
        -o -name '*.ko.*' -o -name '*.mod.c' \
        -o -name '*.symtypes' -o -name 'modules.order' \
        -o -name modules.builtin -o -name '.tmp_*.o*' \
        -o -name '*.gcno' \) -type f -print | xargs rm -f
```

### 2. Kbuild系统核心概念

Kbuild是Linux内核特有的构建系统，它扩展了传统的Makefile功能：

```makefile
# 定义目标文件
obj-y += main.o
obj-y += init.o
obj-y += version.o

# 条件编译
obj-$(CONFIG_PCI) += pci.o
obj-$(CONFIG_ACPI) += acpi.o

# 目录递归构建
obj-y += drivers/
obj-y += net/
obj-y += fs/

# 模块构建
obj-m += mymodule.o

# 多文件模块
mymodule-objs := file1.o file2.o file3.o
obj-m += mymodule.o
```

### 3. 构建变量和规则

```makefile
# 编译器定义
CC              = $(CROSS_COMPILE)gcc
LD              = $(CROSS_COMPILE)ld
AR              = $(CROSS_COMPILE)ar
NM              = $(CROSS_COMPILE)nm
STRIP           = $(CROSS_COMPILE)strip
OBJCOPY         = $(CROSS_COMPILE)objcopy
OBJDUMP         = $(CROSS_COMPILE)objdump

# 编译选项
CFLAGS_KERNEL   =
AFLAGS_KERNEL   =
LDFLAGS_vmlinux =
CFLAGS_MODULE   =
AFLAGS_MODULE   =

# 内核构建规则
quiet_cmd_cc_o_c = CC $(quiet_modtag) $@
      cmd_cc_o_c = $(CC) $(c_flags) -c -o $@ $<

$(obj)/%.o: $(src)/%.c
    $(call cmd,force_checksrc)
    $(call if_changed_rule,cc_o_c)

quiet_cmd_as_o_S = AS $(quiet_modtag) $@
      cmd_as_o_S = $(CC) $(a_flags) -c -o $@ $<

$(obj)/%.o: $(src)/%.S
    $(call if_changed_rule,as_o_S)

# 链接规则
quiet_cmd_ld = LD $@
      cmd_ld = $(LD) $(ld_flags) $(LDFLAGS) $(LDFLAGS_$(@F)) \
               $(filter-out FORCE,$^) -o $@

# 模块构建规则
quiet_cmd_modpost = MODPOST $@
      cmd_modpost = scripts/mod/modpost $(modpost_flags) \
                    $(filter-out FORCE,$^)

PHONY += __modpost
__modpost: $(modules:.ko=.o) FORCE
    $(call cmd,modpost)
```

## Kconfig配置系统实现

### 1. Kconfig语法

Kconfig使用特定的语法来定义配置选项：

```kconfig
# 主菜单标题
mainmenu "Linux Kernel Configuration"

# 配置选项类型
config MODVERSIONS
    bool "Module versioning support"
    depends on MODULES
    help
      Usually, you have to use modules compiled with your kernel.
      Saying Y here makes it possible to use modules compiled with
      a different kernel version, but you may need to pass the
      option to make.

# 三态配置选项
CONFIG_PCI
    tristate "PCI support"
    default y if !EMBEDDED
    help
      Find out whether you have a PCI motherboard. PCI is the name of a
      bus system, i.e. the way the CPU talks to the other stuff inside
      your box. Other bus systems are ISA, EISA, MicroChannel (MCA) or VESA.
      If you have PCI, say Y, otherwise N.

# 字符串配置选项
CONFIG_LOCALVERSION
    string "Local version - append to kernel release"
    help
      Append an extra string to the end of your kernel version.
      This will show up when you type uname, for example.
      The string you set here will be appended after the contents of
      file localversion* in your object and source tree, in that order.
      Your total string can be a maximum of 64 characters.

# 数字配置选项
CONFIG_LOG_BUF_SHIFT
    int "Kernel log buffer size (16 => 64KB, 17 => 128KB)"
    range 12 21
    default 17
    help
      Select kernel log buffer size as a power of 2.

# 依赖关系
CONFIG_SMP
    bool "Symmetric multi-processing support"
    depends on !UML
    help
      This enables support for systems with more than one CPU. If you have
      a system with only one CPU, like most personal computers, say N. If
      you have a system with more than one CPU, say Y.

config X86_LOCAL_APIC
    def_bool y
    depends on X86_64 || SMP || X86_32_NON_STANDARD || X86_UP_APIC

# 选择依赖
config HAVE_KVM
    bool
    select PREEMPT_NOTIFIERS

config KVM
    bool "Kernel-based Virtual Machine (KVM) support"
    depends on HAVE_KVM
    help
      Support hosting fully virtualized guest machines using hardware
      virtualization extensions. You will need a fairly recent
      processor equipped with virtualization extensions. You will also
      need to select one or more of the processor modules below.

# 菜单结构
menu "Executable file formats"

source "fs/Kconfig.binfmt"

config COMPAT_BINFMT_ELF
    bool
    depends on COMPAT && BINFMT_ELF
    default y

endmenu
```

### 2. Kconfig实现机制

```c
// scripts/kconfig/conf.c - 配置解析器
static void conf_parse(const char *name)
{
    struct symbol *sym;
    int i;

    zconf_initscan(name);

    sym_init();
    _menu_init();
    modules_sym = sym_lookup(NULL, "MODULES");
    if (modules_sym)
        modules_sym->flags |= SYMBOL_AUTO;

    if (sym_parse()) {
        fprintf(stderr, "%s: %d: parse error\n", zconf_curname(),
            zconf_lineno());
        exit(1);
    }

    sym_set_change_count(1);
}

// 符号查找
struct symbol *sym_lookup(const char *name, int flags)
{
    struct symbol *symbol;
    const char *ptr;
    char *new_name;
    int hash;

    if (name) {
        if (name[0] && !name[1]) {
            switch (name[0]) {
            case 'y': return &symbol_yes;
            case 'm': return &symbol_mod;
            case 'n': return &symbol_no;
            }
        }
        hash = strhash(name);
        for (symbol = symbol_hash[hash]; symbol; symbol = symbol->next) {
            if (!strcmp(symbol->name, name) &&
                (flags ? symbol->flags & flags
                   : !(symbol->flags & SYMBOL_CONST)))
                return symbol;
        }
        new_name = strdup(name);
    } else {
        new_name = NULL;
        hash = 0;
    }

    symbol = malloc(sizeof(*symbol));
    memset(symbol, 0, sizeof(*symbol));
    symbol->name = new_name;
    symbol->type = S_UNKNOWN;
    symbol->flags = flags;
    symbol->next = symbol_hash[hash];
    symbol_hash[hash] = symbol;

    return symbol;
}

// 依赖关系检查
static void sym_check_deps(struct symbol *sym)
{
    struct symbol *sym2;
    struct property *prop;

    for (prop = sym->prop; prop; prop = prop->next) {
        if (prop->type == P_SELECT) {
            sym2 = prop_get_symbol(prop);
            if (sym2->type != S_UNKNOWN &&
                sym2->type != S_BOOLEAN)
                fprintf(stderr, "error: select of non-boolean '%s'\n",
                    sym2->name);
        }
    }
}
```

### 3. 配置文件生成

```c
// scripts/kconfig/confdata.c - 配置文件处理
int conf_write(const char *name)
{
    FILE *out;
    struct symbol *sym;
    const char *str;
    char *newname;
    char dir[PATH_MAX+1];
    time_t now;
    int use_timestamp = 1;
    char *env;

    dir[0] = 0;
    if (name && name[0]) {
        struct stat st;
        char *slash;

        if (!stat(name, &st) && S_ISDIR(st.st_mode)) {
            strcpy(dir, name);
            strcat(dir, "/");
            name = NULL;
        } else if ((slash = strrchr(name, '/'))) {
            int len = slash - name;
            memcpy(dir, name, len);
            dir[len] = 0;
            name = slash + 1;
        }
    }

    if (!name)
        name = ".config";

    env = getenv("KCONFIG_NOTIMESTAMP");
    if (env && *env)
        use_timestamp = 0;

    newname = conf_get_autoconfig_name();
    if (!stat(newname, &st)) {
        if (!unlink(newname))
            sym_change_count++;
    }

    out = fopen(newname, "w");
    if (!out)
        return 1;

    sym_calc_value(modules_sym);
    sym_calc_value(env_sym);

    fprintf(out, "#\n");
    fprintf(out, "# Automatically generated file; DO NOT EDIT.\n");
    fprintf(out, "# %s\n", name);
    if (use_timestamp)
        fprintf(out, "#\n# %s", ctime(&now));
    fprintf(out, "#\n");

    for_all_symbols(i, sym) {
        sym_calc_value(sym);
        if (!(sym->flags & SYMBOL_WRITE) || !sym->name)
            continue;
        switch (sym->type) {
        case S_BOOLEAN:
        case S_TRISTATE:
            switch (sym_get_tristate_value(sym)) {
            case no:
                break;
            case mod:
                fprintf(out, "CONFIG_%s=m\n", sym->name);
                break;
            case yes:
                fprintf(out, "CONFIG_%s=y\n", sym->name);
                break;
            }
            break;
        case S_STRING:
            str = sym_get_string_value(sym);
            fprintf(out, "CONFIG_%s=\"", sym->name);
            if (str)
                while (*str) {
                    if (*str == '"')
                        fprintf(out, "\\\"");
                    else if (*str == '\\')
                        fprintf(out, "\\\\");
                    else
                        fputc(*str, out);
                    str++;
                }
            fprintf(out, "\"\n");
            break;
        case S_HEX:
            str = sym_get_string_value(sym);
            if (str) {
                fprintf(out, "CONFIG_%s=0x%s\n", sym->name, str);
            } else {
                fprintf(out, "CONFIG_%s=\n", sym->name);
            }
            break;
        case S_INT:
            str = sym_get_string_value(sym);
            if (str) {
                fprintf(out, "CONFIG_%s=%s\n", sym->name, str);
            } else {
                fprintf(out, "CONFIG_%s=\n", sym->name);
            }
            break;
        default:
            break;
        }
    }

    fclose(out);

    return 0;
}
```

## 内核编译完整流程

### 1. 准备阶段

```bash
# 1. 清理构建环境
make mrproper        # 完全清理，包括.config
make clean          # 清理生成的文件但保留.config

# 2. 配置内核
make menuconfig     # 基于文本的配置界面
make xconfig        # 图形配置界面（需要Qt）
make gconfig        # 图形配置界面（需要GTK）
make oldconfig      # 基于现有配置更新
make defconfig      # 使用默认配置
make allnoconfig    # 最小化配置（只选必需的）
make allyesconfig   # 最大化配置（选择所有可选的）

# 3. 检查依赖
make prepare        # 准备构建环境
make scripts        # 构建必需的脚本
```

### 2. 编译阶段

```makefile
# 构建目标定义
vmlinux: $(vmlinux-lds) $(vmlinux-init) $(vmlinux-main) vmlinux.o FORCE
    $(call if_changed_rule,link_vmlinux)

# 构建顺序
1. 基础头文件生成
2. 脚本和工具构建
3. 架构特定代码构建
4. 子系统构建
5. 链接最终内核
```

### 3. 详细构建步骤

```c
// scripts/link-vmlinux.sh - 内核链接脚本
#!/bin/sh

# SPDX-License-Identifier: GPL-2.0
#
# link vmlinux
#
# vmlinux is linked from the objects selected by $(KBUILD_VMLINUX_INIT) and
# $(KBUILD_VMLINUX_MAIN). Most are built-in.o files from top-level directories
# in the kernel tree, others are specified in arch/$(ARCH)/Makefile.
# Ordering when linking is important, and $(KBUILD_VMLINUX_INIT) must be first
# in the list.

# Error out on error
set -e

# Nice output in kbuild format
info()
{
    printf "  %-7s %s\n" "${1}" "${2}"
}

# Link of vmlinux.o
if [ -n "${CONFIG_KALLSYMS}" ]; then
    info LNK vmlinux.o
    ${LD} ${LDFLAGS} -r -o vmlinux.o \
        --start-group \
        ${KBUILD_VMLINUX_INIT} \
        ${KBUILD_VMLINUX_MAIN} \
        --end-group \
        ${KBUILD_VMLINUX_LIBS}
fi

# First version of the kernel
info LNK .tmp_vmlinux1
${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o .tmp_vmlinux1 \
    -T ${lds} ${kallsymso} --start-group \
    ${KBUILD_VMLINUX_INIT} \
    ${KBUILD_VMLINUX_MAIN} \
    --end-group ${KBUILD_VMLINUX_LIBS}

# Generate System.map
info SYSMAP System.map
${NM} -n .tmp_vmlinux1 > System.map

# kallsyms generation
if [ -n "${CONFIG_KALLSYMS}" ]; then
    info KSYM .tmp_kallsyms1.S
    ${KALLSYMS} .tmp_vmlinux1 > .tmp_kallsyms1.S

    info AS .tmp_kallsyms1.o
    ${CC} ${AFLAGS} -c -o .tmp_kallsyms1.o .tmp_kallsyms1.S

    info LNK .tmp_vmlinux2
    ${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o .tmp_vmlinux2 \
        -T ${lds} .tmp_kallsyms1.o --start-group \
        ${KBUILD_VMLINUX_INIT} \
        ${KBUILD_VMLINUX_MAIN} \
        --end-group ${KBUILD_VMLINUX_LIBS}

    info KSYM .tmp_kallsyms2.S
    ${KALLSYMS} .tmp_vmlinux2 > .tmp_kallsyms2.S

    info AS .tmp_kallsyms2.o
    ${CC} ${AFLAGS} -c -o .tmp_kallsyms2.o .tmp_kallsyms2.S

    info LNK .tmp_vmlinux3
    ${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o .tmp_vmlinux3 \
        -T ${lds} .tmp_kallsyms2.o --start-group \
        ${KBUILD_VMLINUX_INIT} \
        ${KBUILD_VMLINUX_MAIN} \
        --end-group ${KBUILD_VMLINUX_LIBS}

    # Do we need kallsyms for the final kernel?
    if [ -n "${CONFIG_KALLSYMS_ALL}" ]; then
        info KSYM .tmp_kallsyms3.S
        ${KALLSYMS} --all-symbols .tmp_vmlinux3 > .tmp_kallsyms3.S

        info AS .tmp_kallsyms3.o
        ${CC} ${AFLAGS} -c -o .tmp_kallsyms3.o .tmp_kallsyms3.S

        info LNK vmlinux
        ${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o vmlinux \
            -T ${lds} .tmp_kallsyms3.o --start-group \
            ${KBUILD_VMLINUX_INIT} \
            ${KBUILD_VMLINUX_MAIN} \
            --end-group ${KBUILD_VMLINUX_LIBS}
    else
        info LNK vmlinux
        ${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o vmlinux \
            -T ${lds} .tmp_kallsyms2.o --start-group \
            ${KBUILD_VMLINUX_INIT} \
            ${KBUILD_VMLINUX_MAIN} \
            --end-group ${KBUILD_VMLINUX_LIBS}
    fi
else
    info LNK vmlinux
    ${LD} ${LDFLAGS} ${LDFLAGS_vmlinux} -o vmlinux \
        -T ${lds} --start-group \
        ${KBUILD_VMLINUX_INIT} \
        ${KBUILD_VMLINUX_MAIN} \
        --end-group ${KBUILD_VMLINUX_LIBS}
fi

# Final strip
if [ -n "${CONFIG_STRIP_ASM_SYMS}" ]; then
    info STRIP vmlinux
    ${STRIP} -s vmlinux
fi

info SYSMAP .tmp_System.map
${NM} -n vmlinux > .tmp_System.map

# Fixup the timestamps
if [ -n "${CONFIG_KALLSYMS}" ]; then
    info KSYM .tmp_vmlinux.kallsyms1
    ${KALLSYMS} .tmp_vmlinux1 > .tmp_vmlinux.kallsyms1
    info KSYM .tmp_vmlinux.kallsyms2
    ${KALLSYMS} .tmp_vmlinux2 > .tmp_vmlinux.kallsyms2
    if [ -n "${CONFIG_KALLSYMS_ALL}" ]; then
        info KSYM .tmp_vmlinux.kallsyms3
        ${KALLSYMS} .tmp_vmlinux3 > .tmp_vmlinux.kallsyms3
    fi
fi
```

### 4. 模块构建

```makefile
# modules: 构建所有模块
modules: $(vmlinux-dirs)
    $(Q)$(MAKE) $(build)=$(build-dir) $(build-target)

# modpost: 模块后处理
quiet_cmd_modpost = MODPOST $@
      cmd_modpost = scripts/mod/modpost $(modpost_flags) \
                    $(filter-out FORCE,$^)

PHONY += __modpost
__modpost: $(modules:.ko=.o) FORCE
    $(call cmd,modpost)

# 模块安装
modules_install: _modinst_ _modinst_post
```

## 交叉编译支持

### 1. 交叉编译配置

```makefile
# 交叉编译器前缀
CROSS_COMPILE ?= $(CONFIG_CROSS_COMPILE:"%"=%)

# 架构设置
ARCH ?= $(SUBARCH)

# 示例：ARM交叉编译
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabi-

# 示例：x86_64交叉编译
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-gnu-
```

### 2. 目标平台配置

```makefile
# arch/x86/Makefile - x86架构特定构建规则
BITS := 32
RCX := 32

ifeq ($(CONFIG_X86_32),y)
        BITS := 32
        KBUILD_CFLAGS += -m32 -march=i686
        KBUILD_AFLAGS += -m32
        KBUILD_LDFLAGS += -m elf_i386
        LDFLAGS := -m elf_i386
        LDFLAGS_vmlinux := -m elf_i386
        UTS_MACHINE := i386
        CHECKFLAGS += -D__i386__
else
        BITS := 64
        KBUILD_CFLAGS += -m64
        KBUILD_AFLAGS += -m64
        KBUILD_LDFLAGS += -m elf_x86_64
        LDFLAGS := -m elf_x86_64
        LDFLAGS_vmlinux := -m elf_x86_64
        UTS_MACHINE := x86_64
        CHECKFLAGS += -D__x86_64__
endif

export BITS

# 头文件路径
ifeq ($(CONFIG_X86_32),y)
        CHECKFLAGS += -D__i386__
else
        CHECKFLAGS += -D__x86_64__
endif

# 架构特定目标
core-y += kernel/ mm/ fs/ ipc/ security/ crypto/ block/

core-y += arch/x86/ \
        arch/x86/kernel/ \
        arch/x86/mm/ \
        arch/x86/crypto/ \
        arch/x86/oprofile/ \
        arch/x86/power/ \
        arch/x86/video/

drivers-$(CONFIG_OPROFILE) += arch/x86/oprofile/

drivers-$(CONFIG_PM) += arch/x86/power/

drivers-$(CONFIG_FB) += arch/x86/video/

# 引导映像
boot := arch/x86/boot

PHONY += zImage bzImage compressed zlilo bzlilo \
         zdisk bzdisk fdimage fdimage144 fdimage288 isoimage install

# 默认构建目标
all: bzImage

# 内核映像
bzImage: vmlinux
ifeq ($(CONFIG_X86_DECODER_SELFTEST),y)
    $(Q)$(MAKE) $(build)=arch/x86/tools posttest
endif
    $(Q)$(MAKE) $(build)=$(boot) $(boot)/bzImage
```

### 3. 设备树支持

```makefile
# 设备树编译规则
ifeq ($(CONFIG_OF),y)
        core-y += arch/arm/boot/dts/

# 设备树编译
DTC ?= $(objtree)/scripts/dtc/dtc

# Quiet the output of DTC
DTC_FLAGS += -Wno-unit_address_vs_reg

# Disable noisy checks by default
ifeq ($(findstring 1,$(KBUILD_EXTRA_WARN)),)
DTC_FLAGS += -Wno-unit_address_format -Wno-simple_bus_reg
DTC_FLAGS += -Wno-avoid_unnecessary_addr_size
DTC_FLAGS += -Wno-alias_paths -Wno-graph_child_address
DTC_FLAGS += -Wno-graph_port -Wno-unique_unit_address
endif

DTC_FLAGS += $(DTC_FLAGS_$(basetarget))

# Generate an assembly file to wrap the output of the device tree compiler
quiet_cmd_dt_S_dtb= DTB     $@
cmd_dt_S_dtb= \
( \
    echo '\#include <asm-generic/vmlinux.lds.h>'; \
    echo '.section .dtb.init.rodata,"a"'; \
    echo '.balign STRUCT_ALIGNMENT'; \
    echo '.global __dtb_$(subst -,_,$(*F))_begin'; \
    echo '__dtb_$(subst -,_,$(*F))_begin:'; \
    echo '.incbin "$<"'; \
    echo '__dtb_$(subst -,_,$(*F))_end:'; \
    echo '.global __dtb_$(subst -,_,$(*F))_size'; \
    echo '.long __dtb_$(subst -,_,$(*F))_end - __dtb_$(subst -,_,$(*F))_begin'; \
) > $@

$(obj)/%.dtb.S: $(obj)/%.dtb
    $(call cmd,dt_S_dtb)

quiet_cmd_dtc = DTC     $@
cmd_dtc = mkdir -p $(dir ${dtc-tmp}) ; \
    $(DTC) -O dtb -o $@ -b 0 \
        $(addprefix -i,$(dir $<) $(DTC_INCLUDE)) $(DTC_FLAGS) \
        -d $(depfile).dtc.tmp $(dtc-tmp) $< ;

$(obj)/%.dtb: $(src)/%.dts $(DTC) FORCE
    $(call if_changed_dep,dtc)
endif
```

## 实际应用示例

### 1. 自定义Makefile示例

```makefile
# 为特定模块创建的Makefile
obj-m += my_driver.o

# 多文件模块
my_driver-objs := main.o utils.o protocol.o

# 包含目录
ccflags-y := -I$(src)/include
ccflags-y += -I$(KERNELDIR)/include

# 编译器标志
ccflags-y += -Wall -Werror
ccflags-y += -DDEBUG -g

# 构建规则
all:
    make -C $(KERNELDIR) M=$(PWD) modules

clean:
    make -C $(KERNELDIR) M=$(PWD) clean

# 安装规则
install:
    make -C $(KERNELDIR) M=$(PWD) modules_install

# 测试规则
test:
    sudo insmod my_driver.ko
    sudo rmmod my_driver
```

### 2. 内核配置示例

```kconfig
# 自定义Kconfig文件
menu "My Custom Driver"

config MY_DRIVER
    tristate "My Custom Driver Support"
    depends on PCI
    help
      This is my custom driver for PCI devices.

config MY_DRIVER_DEBUG
    bool "Enable Debug Output"
    depends on MY_DRIVER
    default n
    help
      Enable debug output for my driver.

config MY_DRIVER_PROBE_ALL
    bool "Probe All Compatible Devices"
    depends on MY_DRIVER
    default y
    help
      If enabled, the driver will attempt to probe all compatible
      devices, not just the first one found.

endmenu
```

### 3. 自动化构建脚本

```bash
#!/bin/bash
# build-kernel.sh - 自动化内核构建脚本

set -e

# 配置变量
KERNEL_VERSION="5.15.0"
ARCH="x86_64"
CROSS_COMPILE="x86_64-linux-gnu-"
JOBS=$(nproc)
BUILD_DIR="build"
CONFIG_FILE="configs/my_defconfig"

# 创建构建目录
mkdir -p $BUILD_DIR

# 设置环境变量
export ARCH=$ARCH
export CROSS_COMPILE=$CROSS_COMPILE
export KBUILD_OUTPUT=$BUILD_DIR

# 清理构建环境
echo "Cleaning build environment..."
make mrproper

# 复制配置文件
echo "Applying configuration..."
cp $CONFIG_FILE $BUILD_DIR/.config

# 更新配置
echo "Updating configuration..."
make olddefconfig

# 开始构建
echo "Building kernel with $JOBS jobs..."
make -j$JOBS

# 构建模块
echo "Building modules..."
make modules -j$JOBS

# 安装模块
echo "Installing modules..."
sudo make modules_install

# 安装内核
echo "Installing kernel..."
sudo make install

echo "Build completed successfully!"
```

### 4. 构建问题诊断

```bash
# 检查构建环境
make help          # 显示可用目标
make V=1           # 详细输出
make V=2           # 更详细的输出

# 调试构建问题
make drivers/gpu/drm/i915/whatever.o  # 构建特定文件
make W=1          # 显示额外警告
make C=1          # 使用 sparse 检查

# 检查依赖
make listnewconfig  # 列出新选项
make oldnoconfig   # 保持旧配置，新选项设为N

# 性能分析
make time          # 显示构建时间
time make -j4      # 测量构建时间
```

## 总结

Linux内核的构建系统是一个复杂但功能强大的系统，它通过Makefile和Kconfig的组合提供了灵活的配置和构建能力。理解这些构建工具的工作原理对于内核开发和调试至关重要。

Kbuild系统简化了内核模块的构建过程，而Kconfig系统提供了丰富的配置选项。交叉编译支持使得内核可以在不同架构上构建和运行。通过掌握这些工具，开发者可以更有效地参与内核开发和维护。

实际应用中，合理的构建脚本和配置管理可以大大提高开发效率。通过本节的学习，读者应该能够理解内核构建的完整流程，并能够根据需要进行定制和扩展。