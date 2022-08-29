#ifndef __SUNXI_PANICPART_H
#define __SUNXI_PANICPART_H

#include <linux/types.h>

enum sunxi_flash {
	SUNXI_FLASH_ERROR = 0,
	SUNXI_FLASH_MMC,
	SUNXI_FLASH_NAND,
	SUNXI_FLASH_NOR,
};

struct panic_part {
	enum sunxi_flash type;
	const char *bdev;
	size_t start_sect;
	size_t sects;

	ssize_t (*panic_read)(struct panic_part *part, loff_t sec_off,
			size_t sec_cnt, char *buf);
	ssize_t (*panic_write)(struct panic_part *part, loff_t sec_off,
			size_t sec_cnt, const char *buf);

	void *private;
};

#ifdef CONFIG_SUNXI_PANICPART
extern int sunxi_panicpart_init(struct panic_part *part);
extern int sunxi_parse_blkdev(char *bdev, int len);
#else
int sunxi_panicpart_init(struct panic_part *part) {return -1;}
int sunxi_parse_blkdev(char *bdev, int len) {return -1;}
#endif

#endif
