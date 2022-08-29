ifneq ($(__target/allwinner/v313-common/BoardConfigCommon.mk_inc),1)
__target/allwinner/v313-common/BoardConfigCommon.mk_inc=1

-include target/allwinner/generic/common.mk

TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_CPU_SMP := false
TARGET_LINUX_VERSION:=4.9
TARGET_UBOOT_VERSION:=2014.07
TARGET_ARCH := arm
TARGET_ARCH_VARIANT := armv7-a-neon
TARGET_CPU_VARIANT := cortex-a7

TARGET_ARCH_PACKAGES := sunxi

TARGET_BOARD_PLATFORM := v313

endif #__target/allwinner/v313-common/BoardConfigCommon.mk_inc
