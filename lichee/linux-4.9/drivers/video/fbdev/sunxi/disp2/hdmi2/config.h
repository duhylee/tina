/*
 * linux-3.10/drivers/video/sunxi/disp2/hdmi2/config.h
 *
 * Copyright (c) 2007-2017 Allwinnertech Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _CONFIG_H_
#define  _CONFIG_H_

/*__FPGA_PLAT__*/

#ifdef CONFIG_ARCH_SUN8IW16
#define SUPPORT_ONLY_HDMI14
#define USE_CSC
#define TCON_PAN_SEL
#endif

#endif
