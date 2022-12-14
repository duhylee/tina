#
# Copyright (C) 2010-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=e2fsprogs
PKG_CPE_ID:=cpe:/a:e2fsprogs_project:e2fsprogs
PKG_VERSION:=1.44.3
PKG_HASH:=5d899f7d30f481cc0c6a049ebe26ebe145f1b524182ea1ecde4086162d4e4bb6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=@KERNEL/linux/kernel/people/tytso/e2fsprogs/v$(PKG_VERSION)/

HOST_BUILD_PARALLEL:=1
HOST_PREPARED_DEPENDS += CONFIG_USE_SELINUX

include $(BUILD_DIR)/host-build.mk

HOST_CFLAGS += $(FPIC)

HOST_CONFIGURE_ARGS += \
	--disable-elf-shlibs \
	--enable-libuuid \
	--disable-tls \
	--disable-nls

define Host/Prepare
	$(call Host/Prepare/Default)
	rm -rf $(HOST_BUILD_DIR)/doc
endef

define Host/Compile
	$(call Host/Compile/Default)
ifneq ($(CONFIG_USE_SELINUX),)
	$(MAKE) -C $(HOST_BUILD_DIR)/contrib/android \
		CFLAGS="$(HOST_CFLAGS)" \
		LDFLAGS="$(HOST_LDFLAGS)"
endif
endef

define Host/Install
	$(Host/Install/Default)
	$(MAKE) -C $(HOST_BUILD_DIR)/lib/uuid install
	mkdir -p $(STAGING_DIR_HOST)/include/e2fsprogs
	$(CP) $(STAGING_DIR_HOST)/include/uuid $(STAGING_DIR_HOST)/include/e2fsprogs/
	rm -rf $(STAGING_DIR_HOST)/include/uuid
	$(INSTALL_DATA) $(HOST_BUILD_DIR)/lib/uuid/libuuid.a $(STAGING_DIR_HOST)/lib/

ifneq ($(CONFIG_USE_SELINUX),)
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/contrib/android/e2fsdroid $(STAGING_DIR_HOST)/bin
endif
endef

define Host/Clean
	rm -f $(STAGING_DIR_HOST)/bin/e2fsck
	rm -f $(STAGING_DIR_HOST)/bin/tune2fs
ifneq ($(CONFIG_USE_SELINUX),)
	rm -f $(STAGING_DIR_HOST)/bin/e2fsdroid
endif
endef

$(eval $(call HostBuild))
