#
# Copyright (C) 2015-2016 Allwinner
#
# This is free software, licensed under the GNU General Public License v2.
# See /build/LICENSE for more information.

TEST_MENU:=Test module Support

define KernelPackage/sunxi-timer
  SUBMENU:=$(TEST_MENU)
  TITLE:=sunxi timer test support
  DEPENDS:=@TARGET_r6_mic2
KCONFIG:=CONFIG_SUNXI_TIMER_TEST
  FILES:=$(LINUX_DIR)/drivers/char/timer_test/sunxi_timer_test.ko
  AUTOLOAD:=$(call AutoProbe, sunxi_timer_test)
endef

define KernelPackage/sunxi-timer/description
 Kernel modules for sunxi timer test support
endef

$(eval $(call KernelPackage,sunxi-timer))

define KernelPackage/xradio-xr819
  SUBMENU:=$(WIRELESS_MENU)
  TITLE:=xr819 support
  DEPENDS:=@TARGET_r6_mic2 +kmod-cfg80211
  FILES:=$(LINUX_DIR)/drivers/net/wireless/xradio/wlan/xradio_core.ko
  FILES+=$(LINUX_DIR)/drivers/net/wireless/xradio/wlan/xradio_wlan.ko
  FILES+=$(LINUX_DIR)/drivers/net/wireless/xradio/umac/xradio_mac.ko
  AUTOLOAD:=$(call AutoProbe, xradio_mac xradio_core xradio_wlan)
endef

define KernelPackage/xradio-xr819/description
 Kernel modules for Allwinnertech XR819  support
endef

$(eval $(call KernelPackage,xradio-xr819))

define KernelPackage/touchscreen-atmel-mxt
  SUBMENU:=$(INPUT_MODULES_MENU)
  TITLE:=Atmel MXT  support
  DEPENDS:= +kmod-input-core
  KCONFIG:= \
	CONFIG_INPUT_TOUCHSCREEN \
	CONFIG_INPUT_TOUCHSCREEN_ATMEL_MXT
  FILES:=$(LINUX_DIR)/drivers/input/touchscreen/atmel_mxt_ts.ko
  AUTOLOAD:=$(call AutoProbe,atmel_mxt_ts.ko)
endef

define KernelPackage/touchscreen-atmel-mxt/description
 Enable support for Atmel MXT touchscreen port.
endef

$(eval $(call KernelPackage,touchscreen-atmel-mxt))

define KernelPackage/touchscreen-icn85xx
  SUBMENU:=$(INPUT_MODULES_MENU)
  TITLE:= ICN85XX support
  DEPENDS:= +kmod-input-core
  KCONFIG:= \
	CONFIG_INPUT_TOUCHSCREEN \
	CONFIG_INPUT_TOUCHSCREEN_ICN85XX_TS
  FILES:=$(LINUX_DIR)/drivers/input/touchscreen/icn85xx/icn85xx_ts.ko
  AUTOLOAD:=$(call AutoProbe,icn85xx_ts.ko)
endef

define KernelPackage/touchscreen-icn85xx/description
 Enable support for ICN85XX touchscreen port.
endef

$(eval $(call KernelPackage,touchscreen-icn85xx))
