#!/bin/bash

help_info()
{
	echo -e "Usage: $0 <rootfs> <verity_block>"
}

ROOT_DIR=$TINA_BUILD_TOP
OUT_DIR=$TINA_BUILD_TOP/out/$TARGET_BOARD
HOST_DIR=$TINA_BUILD_TOP/out/host/bin

if [ ! -d "$OUT_DIR/verity" ]; then
	echo "Please run ./dm-verity-key.sh first to generate keys!"
	exit
fi

if [ $# -eq 2 ]; then
	IN=$1
	OUT=$2
else
	# default value
	IN=$OUT_DIR/rootfs.img
	OUT=$OUT_DIR/verity/verity_block
fi

VERITY_DIR=`dirname $OUT`
BLK_SIZE=4096

get_blk_size()
{
	local size=`du -b $1 | awk '{print $1}'`

	if [ `expr ${size} % ${BLK_SIZE}` = "0" ]; then
		local blks=`(expr ${size} / ${BLK_SIZE})`
	else
		local blks=`(expr ${size} / ${BLK_SIZE} + 1 )`
	fi

	echo $blks
}

rm -rf $VERITY_DIR/rootfs_hash_table $VERITY_DIR/rootfs_hash_tree.bin $VERITY_DIR/sign $VERITY_DIR/hash_block $VERITY_DIR/verity_block

# 1. gen rootfs_hash_tree.bin and rootfs_hash_table
$HOST_DIR/veritysetup format $IN $VERITY_DIR/rootfs_hash_tree.bin > $VERITY_DIR/rootfs_hash_table

# 2. gen signature of rootfs_hash_table
openssl dgst -sha256 -binary -sign $VERITY_DIR/keys/rsa_key.pair $VERITY_DIR/rootfs_hash_table > $VERITY_DIR/sign

# verity_block structure
# 0----------------------------4K-----------------------4K*N--------------------------4K*M
# <sign><hash table size><000...><rootfs_hash_table><000...><rootfs_hash_tree.bin><000...>

# 3. merge verity_block
SIGN_BLK=`get_blk_size $VERITY_DIR/sign`
TABLE_BLK=`get_blk_size $VERITY_DIR/rootfs_hash_table`
TREE_BLK=`get_blk_size $VERITY_DIR/rootfs_hash_tree.bin`

# 3.1 copy sign
dd if=$VERITY_DIR/sign of=$VERITY_DIR/hash_block bs=${BLK_SIZE} count=${SIGN_BLK} >/dev/null 2>&1

# 3.2 save rootfs_hash_table size to the back of sign
TABLE_SIZE=`du -b $VERITY_DIR/rootfs_hash_table | awk '{print $1}'`
HIGH_BYTES=`expr $TABLE_SIZE / 256 `
LOW_BYTES=`expr $TABLE_SIZE % 256 `
if [ $HIGH_BYTES -gt 256 ]; then
	echo "ERROR rootfs_hash_table size should < 64KB"
	exit
fi
HIGH_BYTES_H=`echo "obase=16;ibase=10;$HIGH_BYTES" | bc`
LOW_BYTES_H=`echo "obase=16;ibase=10;$LOW_BYTES" | bc`
echo -e -n "\x$LOW_BYTES_H\x$HIGH_BYTES_H" >> $VERITY_DIR/hash_block

# 3.3 copy rootfs_hash_table
dd if=$VERITY_DIR/rootfs_hash_table of=$VERITY_DIR/hash_block  bs=${BLK_SIZE} seek=${SIGN_BLK} count=${TABLE_BLK} > /dev/null 2>&1

# 3.4 copy rootfs_hash_tree.bin
dd if=$VERITY_DIR/rootfs_hash_tree.bin of=$VERITY_DIR/hash_block  bs=${BLK_SIZE} seek=`expr ${SIGN_BLK} + ${TABLE_BLK}` count=${TREE_BLK} > /dev/null 2>&1

dd of=${OUT} if=$VERITY_DIR/hash_block bs=${BLK_SIZE} count=`expr ${SIGN_BLK} + ${TABLE_BLK} + ${TREE_BLK}`>/dev/null 2>&1

