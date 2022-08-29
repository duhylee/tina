$(call inherit-product-if-exists, target/allwinner/v459-common/v459-common.mk)

PRODUCT_PACKAGES +=

PRODUCT_COPY_FILES +=

PRODUCT_AAPT_CONFIG := large xlarge hdpi xhdpi
PRODUCT_AAPT_PERF_CONFIG := xhdpi
PRODUCT_CHARACTERISTICS := musicbox

PRODUCT_BRAND := allwinner
PRODUCT_NAME := v459_qaqc
PRODUCT_DEVICE := v459-qaqc
PRODUCT_MODEL := Allwinner v459 qaqc board
