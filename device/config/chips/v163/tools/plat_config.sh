#!/bin/bash

#set -e

#
# 3:ddr3 4:ddr4 7:lpddr3 8:lpddr4
#
DRAM_TYPE=0
DRAM_NAME="null"
PACK_CHIP="sun8iw16p1"


copy_boot_file()
{
	DRAM_TYPE=`awk  '$0~"dram_type"{printf"%d", $3}' ${LICHEE_PACK_OUT_DIR}/sys_config.fex`

	case $DRAM_TYPE in
		3) DRAM_NAME="ddr3"
		;;
		4) DRAM_NAME="ddr4"
		;;
		7) DRAM_NAME="lpddr3"
		;;
		8) DRAM_NAME="lpddr4"
		;;
		*) DRAM_NAME="unknow"
		exit 0
		;;
	esac

	prefix_path=${LICHEE_CHIP_CONFIG_DIR}/bin
	target_path=${LICHEE_PACK_OUT_DIR}
	plat_boot_file_list=(
		$prefix_path/boot0_nand_${PACK_CHIP}_${DRAM_NAME}.bin:${target_path}/boot0_nand.fex
		$prefix_path/boot0_sdcard_${PACK_CHIP}_${DRAM_NAME}.bin:${target_path}/boot0_sdcard.fex
		$prefix_path/boot0_spinor_${PACK_CHIP}_${DRAM_NAME}.bin:${target_path}/boot0_spinor.fex
		$prefix_path/fes1_${PACK_CHIP}_${DRAM_NAME}.bin:${target_path}/fes1.fex
		$prefix_path/sboot_${PACK_CHIP}_${DRAM_NAME}.bin:${target_path}/sboot.bin
		$prefix_path/scp_${DRAM_NAME}.bin:${target_path}/scp.fex
	)


	printf "copying boot file for  ${DRAM_NAME}\n"
	for file in ${plat_boot_file_list[@]} ; do
		src_file=`echo $file | awk -F: '{print $1}'`
		dst_file=`echo $file | awk -F: '{print $2}'`
		#echo "${src_file} --> ${dst_file}"
		cp -f ${src_file}  ${dst_file} 2> /dev/null
	done
}

copy_boot_file
