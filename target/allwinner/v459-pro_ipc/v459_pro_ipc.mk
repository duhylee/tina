$(call inherit-product-if-exists, target/allwinner/v459-common/v459-common.mk)

PRODUCT_PACKAGES +=

PRODUCT_COPY_FILES +=

PRODUCT_AAPT_CONFIG := large xlarge hdpi xhdpi
PRODUCT_AAPT_PERF_CONFIG := xhdpi
PRODUCT_CHARACTERISTICS := musicbox

PRODUCT_BRAND := allwinner
PRODUCT_NAME := v459_pro_ipc
PRODUCT_DEVICE := v459-pro_ipc
PRODUCT_MODEL := Allwinner v459 pro_ipc board
