#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Main makefile for the host tools
#
curdir:=tools

# subdirectories to descend into
tools-y :=

ifeq ($(CONFIG_EXTERNAL_TOOLCHAIN),)
  BUILD_TOOLCHAIN := y
  ifdef CONFIG_GCC_USE_GRAPHITE
    ifneq ($(CONFIG_GCC_VERSION_4_8),)
      ifeq ($(CONFIG_GCC_USE_SYSTEM_PPL_CLOOG),)
        BUILD_PPL_CLOOG = y
      endif
    else
      BUILD_ISL = y
    endif
  endif
endif
tools-$(BUILD_TOOLCHAIN) += gmp mpfr mpc libelf expat
tools-y += m4 libtool autoconf automake flex bison pkg-config sed mklibs flux
tools-y += sstrip make-ext4fs e2fsprogs mtd-utils mkimage
tools-y += firmware-utils patch-image patch quilt padjffs2
tools-y += mm-macros missing-macros xz cmake scons bc findutils gengetopt patchelf
tools-y += mtools dosfstools
tools-y += lzma squashfs4 pack-bintools lzo lzop
#tools-y += lzma squashfs4 pack-bintools lzo lzop bsdiff
tools-$(BUILD_PPL_CLOOG) += ppl cloog
tools-$(BUILD_ISL) += isl
tools-$(CONFIG_USE_SPARSE) += sparse
tools-$(CONFIG_USE_SELINUX) += pcre selinux

# builddir dependencies
$(curdir)/bison/compile := $(curdir)/flex/install
$(curdir)/flex/compile := $(curdir)/libtool/install
$(curdir)/pkg-config/compile := $(curdir)/sed/install
$(curdir)/libtool/compile := $(curdir)/sed/install $(curdir)/m4/install $(curdir)/autoconf/install $(curdir)/automake/install $(curdir)/missing-macros/install
$(curdir)/squashfs/compile := $(curdir)/lzma-old/install
ifeq ($(CONFIG_USE_SELINUX),)
$(curdir)/squashfs4/compile := $(curdir)/xz/install
else
$(curdir)/squashfs4/compile := $(curdir)/xz/install $(curdir)/selinux/install
endif
$(curdir)/quilt/compile := $(curdir)/sed/install $(curdir)/autoconf/install $(curdir)/findutils/install
$(curdir)/autoconf/compile := $(curdir)/m4/install
$(curdir)/automake/compile := $(curdir)/m4/install $(curdir)/autoconf/install $(curdir)/pkg-config/install $(curdir)/xz/install
$(curdir)/gmp/compile := $(curdir)/libtool/install
$(curdir)/mpc/compile := $(curdir)/mpfr/install $(curdir)/gmp/install
$(curdir)/mpfr/compile := $(curdir)/gmp/install
$(curdir)/ppl/compile := $(curdir)/gmp/install
$(curdir)/cloog/compile := $(curdir)/ppl/install
$(curdir)/mtd-utils/compile := $(curdir)/e2fsprogs/install $(curdir)/xz/install
$(curdir)/mkimage/compile := $(curdir)/sed/install
$(curdir)/mklibs/compile := $(curdir)/libtool/install
$(curdir)/upslug2/compile := $(curdir)/libtool/install
$(curdir)/mm-macros/compile := $(curdir)/libtool/install
$(curdir)/missing-macros/compile := $(curdir)/autoconf/install
ifeq ($(CONFIG_USE_SELINUX),)
$(curdir)/e2fsprogs/compile := $(curdir)/libtool/install
else
$(curdir)/e2fsprogs/compile := $(curdir)/libtool/install $(curdir)/selinux/install
endif
$(curdir)/libelf/compile := $(curdir)/libtool/install
$(curdir)/sdcc/compile := $(curdir)/bison/install
$(curdir)/padjffs2/compile := $(curdir)/findutils/install
$(curdir)/cloog/compile := $(curdir)/ppl/install
$(curdir)/isl/compile := $(curdir)/gmp/install
$(curdir)/bc/compile := $(curdir)/bison/install
$(curdir)/findutils/compile := $(curdir)/bison/install
$(curdir)/gengetopt/compile := $(curdir)/libtool/install
$(curdir)/patchelf/compile := $(curdir)/libtool/install
$(curdir)/flux/compile := $(curdir)/libtool/install
$(curdir)/lzo/compile := $(curdir)/libtool/install
$(curdir)/lzop/compile := $(curdir)/lzo/install
#$(curdir)/bsdiff/compile := $(curdir)/bsdiff/install
$(curdir)/pcre/compile := $(curdir)/libtool/install
$(curdir)/selinux/compile := $(curdir)/pcre/install

ifneq ($(CONFIG_CCACHE)$(CONFIG_SDK),)
$(foreach tool, $(filter-out patch,$(tools-y)), $(eval $(curdir)/$(tool)/compile += $(curdir)/ccache/install))
tools-y += ccache
endif

# in case there is no patch tool on the host we need to make patch tool a
# dependency for tools which have patches directory
$(foreach tool, $(tools-y), $(if $(wildcard $(curdir)/$(tool)/patches),$(eval $(curdir)/$(tool)/compile += $(curdir)/patch/install)))

$(foreach tool, $(tools-y), $(eval $(curdir)/$(tool)/compile += $(curdir)/tar/install))
tools-y += tar

$(curdir)/tar/compile := $(curdir)/flock/install
tools-y += flock

$(curdir)/builddirs := $(tools-y) $(tools-dep) $(tools-)
$(curdir)/builddirs-default := $(tools-y)

ifndef DUMP_TARGET_DB
define PrepareStaging
	@for dir in $(1); do ( \
		$(if $(QUIET),,set -x;) \
		mkdir -p "$$dir"; \
		cd "$$dir"; \
		mkdir -p bin lib include stamp; \
	); done
endef

# preparatory work
$(STAGING_DIR)/.prepared: $(TMP_DIR)/.build
	$(call PrepareStaging,$(STAGING_DIR))
	mkdir -p $(COMPILE_DIR)/stamp
	touch $@

$(STAGING_DIR_HOST)/.prepared: $(TMP_DIR)/.build
	$(call PrepareStaging,$(STAGING_DIR_HOST))
	mkdir -p $(COMPILE_DIR_HOST)/stamp $(STAGING_DIR_HOST)/include/sys
	$(INSTALL_DATA) $(TOPDIR)/tools/include/*.h $(STAGING_DIR_HOST)/include/
	$(INSTALL_DATA) $(TOPDIR)/tools/include/sys/*.h $(STAGING_DIR_HOST)/include/sys/
	ln -sf lib $(STAGING_DIR_HOST)/lib64
	touch $@

endif

$(curdir)//prepare = $(STAGING_DIR)/.prepared $(STAGING_DIR_HOST)/.prepared
$(curdir)//compile = $(STAGING_DIR)/.prepared $(STAGING_DIR_HOST)/.prepared

# prerequisites for the individual targets
$(curdir)/ := .config prereq
$(curdir)//install = $(1)/compile

tools_enabled = $(foreach tool,$(sort $(tools-y) $(tools-)),$(if $(filter $(tool),$(tools-y)),y,n))
$(eval $(call stampfile,$(curdir),tools,install,,_$(subst $(space),,$(tools_enabled))))
$(eval $(call subdir,$(curdir)))
