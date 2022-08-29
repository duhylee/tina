#
# Copyright (C) 2006-2007 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(BUILD_DIR)/host.mk
include $(BUILD_DIR)/prereq.mk

ifneq ($(DUMP),1)
  all: compile
endif

export QUILT=1
STAMP_PREPARED:=$(LINUX_DIR)/.prepared
STAMP_CONFIGURED:=$(LINUX_DIR)/.configured
include $(BUILD_DIR)/download.mk
include $(BUILD_DIR)/quilt.mk
include $(BUILD_DIR)/kernel-defaults.mk

define Kernel/Prepare
	$(call Kernel/Prepare/Default)
endef

define Kernel/Configure
	$(call Kernel/Configure/Default)
endef

define Kernel/CompileModules
	$(call Kernel/CompileModules/Default)
endef

define Kernel/CompileImage
	$(call Kernel/CompileImage/Default)
	$(call Kernel/CompileImage/Initramfs)
ifneq ($(CONFIG_REDUCE_KERNEL_SIZE),)
	$(SCRIPT_DIR)/reduce-kernel-size.sh c $(LINUX_DIR)/.config
endif
endef

define Kernel/Clean
	$(call Kernel/Clean/Default)
endef

define Download/kernel
  URL:=$(LINUX_SITE)
  FILE:=$(LINUX_SOURCE)
  MD5SUM:=$(LINUX_KERNEL_MD5SUM)
endef

ifdef CONFIG_COLLECT_KERNEL_DEBUG
  define Kernel/CollectDebug
	rm -rf $(KERNEL_BUILD_DIR)/debug
	mkdir -p $(KERNEL_BUILD_DIR)/debug/modules
	$(CP) $(LINUX_DIR)/vmlinux $(KERNEL_BUILD_DIR)/debug/
	-$(CP) \
		$(STAGING_DIR_ROOT)/lib/modules/$(LINUX_VERSION)/* \
		$(KERNEL_BUILD_DIR)/debug/modules/
	$(FIND) $(KERNEL_BUILD_DIR)/debug -type f | $(XARGS) $(KERNEL_CROSS)strip --only-keep-debug
	$(TAR) c -C $(KERNEL_BUILD_DIR) debug \
		$(if $(SOURCE_DATE_EPOCH),--mtime="@$(SOURCE_DATE_EPOCH)") \
		| bzip2 -c -9 > $(TARGET_OUT_DIR)/kernel-debug.tar.bz2
  endef
endif

define BuildKernel
  $(if $(QUILT),$(Build/Quilt))
  $(if $(LINUX_SITE),$(call Download,kernel))

  .NOTPARALLEL:

  $(STAMP_PREPARED): $(if $(LINUX_SITE),$(DL_DIR)/$(LINUX_SOURCE))
	-rm -rf $(KERNEL_BUILD_DIR)
	-mkdir -p $(KERNEL_BUILD_DIR)
	$(Kernel/Prepare)
	touch $$@

  $(KERNEL_BUILD_DIR)/symtab.h: FORCE
	rm -f $(KERNEL_BUILD_DIR)/symtab.h
	touch $(KERNEL_BUILD_DIR)/symtab.h
	+$(MAKE) $(KERNEL_MAKEOPTS) vmlinux
	find $(LINUX_DIR) $(STAGING_DIR_ROOT)/lib/modules -name \*.ko | \
		xargs $(TARGET_CROSS)nm | \
		awk '$$$$1 == "U" { print $$$$2 } ' | \
		sort -u > $(KERNEL_BUILD_DIR)/mod_symtab.txt
	$(TARGET_CROSS)nm -n $(LINUX_DIR)/vmlinux.o | grep ' [rR] __ksymtab' | sed -e 's,........ [rR] __ksymtab_,,' > $(KERNEL_BUILD_DIR)/kernel_symtab.txt
	grep -Ff $(KERNEL_BUILD_DIR)/mod_symtab.txt $(KERNEL_BUILD_DIR)/kernel_symtab.txt > $(KERNEL_BUILD_DIR)/sym_include.txt
	grep -Fvf $(KERNEL_BUILD_DIR)/mod_symtab.txt $(KERNEL_BUILD_DIR)/kernel_symtab.txt > $(KERNEL_BUILD_DIR)/sym_exclude.txt
	( \
		echo '#define SYMTAB_KEEP \'; \
		cat $(KERNEL_BUILD_DIR)/sym_include.txt | \
			awk '{print "KEEP(*(___ksymtab+" $$$$1 ")) \\" }'; \
		echo; \
		echo '#define SYMTAB_KEEP_GPL \'; \
		cat $(KERNEL_BUILD_DIR)/sym_include.txt | \
			awk '{print "KEEP(*(___ksymtab_gpl+" $$$$1 ")) \\" }'; \
		echo; \
		echo '#define SYMTAB_DISCARD \'; \
		cat $(KERNEL_BUILD_DIR)/sym_exclude.txt | \
			awk '{print "*(___ksymtab+" $$$$1 ") \\" }'; \
		echo; \
		echo '#define SYMTAB_DISCARD_GPL \'; \
		cat $(KERNEL_BUILD_DIR)/sym_exclude.txt | \
			awk '{print "*(___ksymtab_gpl+" $$$$1 ") \\" }'; \
		echo; \
	) > $$@

ifneq ($(CONFIG_KERNEL_CONFIG_FILE_SUFFIX_RECOVERY),)
  $(STAMP_CONFIGURED): $(STAMP_PREPARED) $(LINUX_KCONFIG_LIST_RECOVERY) $(TOPDIR)/.config
	$(Kernel/Configure)
	touch $$@
else ifneq ($(CONFIG_KERNEL_CONFIG_FILE_SUFFIX_RAMFS),)
  $(STAMP_CONFIGURED): $(STAMP_PREPARED) $(LINUX_KCONFIG_LIST_RAMFS) $(TOPDIR)/.config
	$(Kernel/Configure)
	touch $$@
else
  $(STAMP_CONFIGURED): $(STAMP_PREPARED) $(LINUX_KCONFIG_LIST) $(TOPDIR)/.config
	$(Kernel/Configure)
	touch $$@
endif

  $(LINUX_DIR)/.modules: $(STAMP_CONFIGURED) $(LINUX_DIR)/.config FORCE
	$(Kernel/CompileModules)
	touch $$@

  $(LINUX_DIR)/.image: $(STAMP_CONFIGURED) $(if $(CONFIG_STRIP_KERNEL_EXPORTS),$(KERNEL_BUILD_DIR)/symtab.h) FORCE
ifdef CONFIG_REDUCE_ROOTFS_SIZE
	$(SCRIPT_DIR)/reduce-rootfs-size.sh d $(TARGET_DIR)
	$(SCRIPT_DIR)/reduce-rootfs-size.sh c $(TARGET_DIR)
endif
	if [ -f "$(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts" ]; then \
		if [ "x$(LINUX_KARCH)" = "xarm" ]; then \
			if [ -f $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/board.dts ]; then \
				cmp -s $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/board.dts $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts || \
					cp $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/board.dts; \
			else \
				cp $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/board.dts; \
			fi \
		elif [ "x$(LINUX_KARCH)" = "xarm64" ]; then \
			if [ -f $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/board.dts ]; then \
				cmp -s $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/sunxi/board.dts $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts || \
					cp $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/sunxi/board.dts; \
			else \
				cp $(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/board.dts $(LINUX_DIR)/arch/$(LINUX_KARCH)/boot/dts/sunxi/board.dts; \
			fi \
		fi \
	fi

	$(Kernel/CompileImage)
	$(Kernel/CollectDebug)
	touch $$@

  mostlyclean: FORCE
	$(Kernel/Clean)

  define BuildKernel
  endef

  download: $(if $(LINUX_SITE),$(DL_DIR)/$(LINUX_SOURCE))
  prepare: $(STAMP_CONFIGURED)
  compile: $(LINUX_DIR)/.modules
	+$(MAKE) -C ../generic/image compile TARGET_BUILD=

  oldconfig menuconfig nconfig: $(STAMP_PREPARED) $(STAMP_CHECKED) FORCE
	rm -f $(LINUX_DIR)/.config.prev
	rm -f $(STAMP_CONFIGURED)
	$(LINUX_RECONF_CMD) > $(LINUX_DIR)/.config
	$(_SINGLE)$(MAKE) -C $(LINUX_DIR) $(KERNEL_MAKEOPTS) $$@
	if [ ! -f "$(LICHEE_CHIP_CONFIG_DIR)/configs/$(subst $(TARGET_PLATFORM)-,,$(TARGET_BOARD))/linux/config-$(KERNEL_PATCHVER)" ]; then \
		$(LINUX_RECONF_DIFF) $(LINUX_DIR)/.config > $(LINUX_RECONFIG_TARGET); \
	else \
		cmp -s $(LINUX_DIR)/.config $(LINUX_RECONFIG_TARGET) || { \
			cp -rf $(LINUX_DIR)/.config $(LINUX_DIR)/arch/$(LINUX_KARCH)/configs/tina_defconfig; \
			$(MAKE) -C $(LINUX_DIR) ARCH=$(LINUX_KARCH) tina_defconfig > /dev/null; \
			cp $(LINUX_DIR)/.config $(LINUX_RECONFIG_TARGET); \
			rm -rf $(LINUX_DIR)/arch/$(LINUX_KARCH)/configs/tina_defconfig; \
		} \
	fi

  recovery_menuconfig: $(STAMP_PREPARED) $(STAMP_CHECKED) FORCE
	rm -f $(LINUX_DIR)/.config.prev
	rm -f $(STAMP_CONFIGURED)
	$(LINUX_RECONF_CMD_RECOVERY) > $(LINUX_DIR)/.config
	$(_SINGLE)$(MAKE) -C $(LINUX_DIR) $(KERNEL_MAKEOPTS) menuconfig
	$(LINUX_RECONF_DIFF_RECOVERY) $(LINUX_DIR)/.config > $(LINUX_RECONFIG_TARGET_RECOVERY)

  ramfs_menuconfig: $(STAMP_PREPARED) $(STAMP_CHECKED) FORCE
	rm -f $(LINUX_DIR)/.config.prev
	rm -f $(STAMP_CONFIGURED)
	$(LINUX_RECONF_CMD_RAMFS) > $(LINUX_DIR)/.config
	$(_SINGLE)$(MAKE) -C $(LINUX_DIR) $(KERNEL_MAKEOPTS) menuconfig
	$(LINUX_RECONF_DIFF_RAMFS) $(LINUX_DIR)/.config > $(LINUX_RECONFIG_TARGET_RAMFS)

  install: $(LINUX_DIR)/.image
	+$(MAKE) -C ../generic/image compile install TARGET_BUILD=

  clean: FORCE
	if [ -d $(LINUX_DIR) ]; then \
		$(_SINGLE)$(MAKE) -C $(LINUX_DIR) $(KERNEL_MAKEOPTS) $$@; \
	fi
	rm -rf $(KERNEL_BUILD_DIR)

  image-prereq:
	@+$(NO_TRACE_MAKE) -s -C ../generic/image prereq TARGET_BUILD=

  prereq: image-prereq

endef
