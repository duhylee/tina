// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021 Davicom Semiconductor,Inc.
 * Davicom DM9051 SPI Fast Ethernet Linux driver
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/crc32.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/iopoll.h>
#include <linux/sunxi-gpio.h>
#include <linux/of_gpio.h>
#include <linux/spi/spi.h>

#include "dm9051.h"

#if 0
//or in [netdevice.h]
void dev_addr_mod(struct net_device *dev, unsigned int offset,
		  const void *addr, size_t len);
//or in [dev_addr_lists.c]
void dev_addr_mod(struct net_device *dev, unsigned int offset,
		  const void *addr, size_t len)
{
	//basic
	memcpy(&dev->dev_addr[offset], addr, len);
	
	//more
	//memcpy(&dev->dev_addr_shadow[offset], addr, len); error: 'struct net_device' has no member named 'dev_addr_shadow'; (V510)
}

//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//or in [etherdevice.h]
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	//memcpy(ndev->dev_addr, addr, 6); //such copy to it instead 
	//=
	dev_addr_mod(dev, 0, addr, 6);
}
#endif

/* spi low level code */
static int
dm9051_xfer(struct board_info *db, u8 cmdphase, u8 *txb, u8 *rxb, unsigned int len)
{
	struct device *dev = &db->spidev->dev;
	int ret = 0;

	db->cmd[0] = cmdphase;
	db->spi_xfer2[0].tx_buf = &db->cmd[0];
	db->spi_xfer2[0].rx_buf = NULL;
	db->spi_xfer2[0].len = 1;
	if (!rxb) {
		db->spi_xfer2[1].tx_buf = txb;
		db->spi_xfer2[1].rx_buf = NULL;
		db->spi_xfer2[1].len = len;
	} else {
		db->spi_xfer2[1].tx_buf = txb;
		db->spi_xfer2[1].rx_buf = rxb;
		db->spi_xfer2[1].len = len;
	}
	ret = spi_sync(db->spidev, &db->spi_msg2);
	if (ret < 0)
		dev_err(dev, "dm9Err spi burst cmd 0x%02x, ret=%d\n", cmdphase, ret);
	return ret;
}

static u8 std_spi_read_reg(struct board_info *db, unsigned int reg)
{
	u8 rxb[1];

	dm9051_xfer(db, DM_SPI_RD | reg, NULL, rxb, 1);
	return rxb[0];
}

/* chip ID display */
static u8 disp_spi_read_reg(struct device *dev, struct board_info *db,
			    unsigned int reg)
{
	u8 rxdata;

	rxdata = std_spi_read_reg(db, reg);
	if (reg == DM9051_PIDL || reg == DM9051_PIDH)
		dev_info(dev, "dm905.MOSI.p.[%02x][..]\n", reg);
	if (reg == DM9051_PIDL || reg == DM9051_PIDH)
		dev_info(dev, "dm905.MISO.e.[..][%02x]\n", rxdata);
	return rxdata;
}

static void std_spi_write_reg(struct board_info *db, unsigned int reg,
			      unsigned int val)
{
	u8 txb[1];

	txb[0] = val;
	dm9051_xfer(db, DM_SPI_WR | reg, txb, NULL, 1);
}

static void std_read_rx_buf_ncpy(struct board_info *db, u8 *buff, unsigned int len)
{
	u8 txb[1];

	dm9051_xfer(db, DM_SPI_RD | DM_SPI_MRCMD, txb, buff, len);
}

static int std_write_tx_buf(struct board_info *db, u8 *buff, unsigned int len)
{
#if NEW_KT515
	db->spi_trans_buf[0] = DM_SPI_WR | DM_SPI_MWCMD;
	memcpy(&db->spi_trans_buf[1], buff, len);
	spi_write(db->spidev, db->spi_trans_buf, len + 1);
#else
	dm9051_xfer(db, DM_SPI_WR | DM_SPI_MWCMD, buff, NULL, len);
#endif
	return 0;
}

/* basic read/write to phy
 */
static int dm_phy_read_func(struct board_info *db, int reg)
{
	int ret;
	u8 check_val;

	iow(db, DM9051_EPAR, DM9051_PHY | reg);
	iow(db, DM9051_EPCR, EPCR_ERPRR | EPCR_EPOS);
	read_poll_timeout(ior, check_val, !(check_val & EPCR_ERRE), 100, 10000,
			  true, db, DM9051_EPCR);
	iow(db, DM9051_EPCR, 0x0);
	ret = (ior(db, DM9051_EPDRH) << 8) | ior(db, DM9051_EPDRL);
	return ret;
}

static void dm_phy_write_func(struct board_info *db, int reg, int value)
{
	u8 check_val;

	iow(db, DM9051_EPAR, DM9051_PHY | reg);
	iow(db, DM9051_EPDRL, value);
	iow(db, DM9051_EPDRH, value >> 8);
	iow(db, DM9051_EPCR, EPCR_EPOS | EPCR_ERPRW);
	read_poll_timeout(ior, check_val, !(check_val & EPCR_ERRE), 100, 10000,
			  true, db, DM9051_EPCR);
	iow(db, DM9051_EPCR, 0x0);
}

/* Read a word data from SROM
 */
static void dm_read_eeprom_func(struct board_info *db, int offset, u8 *to)
{
	u8 check_val;

	mutex_lock(&db->addr_lock);
	iow(db, DM9051_EPAR, offset);
	iow(db, DM9051_EPCR, EPCR_ERPRR);
	read_poll_timeout(ior, check_val, !(check_val & EPCR_ERRE), 100, 10000,
			  true, db, DM9051_EPCR);
	iow(db, DM9051_EPCR, 0x0);
	to[0] = ior(db, DM9051_EPDRL);
	to[1] = ior(db, DM9051_EPDRH);
	mutex_unlock(&db->addr_lock);
}

/* Write a word data to SROM
 */
static void dm_write_eeprom_func(struct board_info *db, int offset, u8 *data)
{
	u8 check_val;

	mutex_lock(&db->addr_lock);
	iow(db, DM9051_EPAR, offset);
	iow(db, DM9051_EPDRH, data[1]);
	iow(db, DM9051_EPDRL, data[0]);
	iow(db, DM9051_EPCR, EPCR_WEP | EPCR_ERPRW);
	read_poll_timeout(ior, check_val, !(check_val & EPCR_ERRE), 100, 10000,
			  true, db, DM9051_EPCR);
	iow(db, DM9051_EPCR, 0);
	mutex_unlock(&db->addr_lock);
}

static int dm9051_phy_read_lock(struct net_device *dev, int phy_reg_unused, int reg)
{
	int val;
	struct board_info *db = netdev_priv(dev);

	mutex_lock(&db->addr_lock);
	val = dm_phy_read_func(db, reg);
	mutex_unlock(&db->addr_lock);
	return val;
}

static void dm9051_phy_write_lock(struct net_device *dev, int phyaddr_unused, int reg, int value)
{
	struct board_info *db = netdev_priv(dev);

	mutex_lock(&db->addr_lock);
	dm_phy_write_func(db, reg, value);
	mutex_unlock(&db->addr_lock);
}

/* read chip id
 */
static unsigned int dm9051_chipid(struct board_info *db)
{
	struct device *dev = &db->spidev->dev;
	unsigned int chipid;

	chipid = iior(dev, db, DM9051_PIDL);
	chipid |= (unsigned int)iior(dev, db, DM9051_PIDH) << 8;
	if (chipid == DM9051_ID)
		return chipid;
	chipid = iior(dev, db, DM9051_PIDL);
	chipid |= (unsigned int)iior(dev, db, DM9051_PIDH) << 8;
	if (chipid == DM9051_ID)
		return chipid;
	dev_dbg(dev, "Read [DM9051_PID] = %04x\n", chipid);
	dev_dbg(dev, "Read [DM9051_PID] error!\n");
	return chipid;
}

static void dm9051_reset(struct board_info *db)
{
	mdelay(2); /* need before NCR_RST */
	ncr_reg_reset(db);
	mdelay(1);
	mbd_reg_byte(db);
	mdelay(1);
	dm_phy_write_func(db, MII_ADVERTISE, ADVERTISE_PAUSE_CAP |
			  ADVERTISE_ALL | ADVERTISE_CSMA); /* for fcr, essential */
	fcr_reg_enable(db);
	ppcr_reg_seeting(db);
	ledcr_reg_setting(db, db->lcr_all);
	intcr_reg_setval(db);
}

/* ESSENTIAL, ensure rxFifoPoint control, disable/enable the interrupt mask
 */
static void dm_imr_disable_lock_essential(struct board_info *db)
{
	mutex_lock(&db->addr_lock);
	imr_reg_stop(db);
	mutex_unlock(&db->addr_lock);
}

static void dm_imr_enable_lock_essential(struct board_info *db)
{
	mutex_lock(&db->addr_lock);
	imr_reg_start(db, db->imr_all); /* rxp to 0xc00 */
	mutex_unlock(&db->addr_lock);
}

/* functions process mac address is major from EEPROM
 */
static void dm9051_read_mac_to_dev(struct net_device *ndev, struct board_info *db)
{
	u8 addr[ETH_ALEN];
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		addr[i] = ior(db, DM9051_PAR + i);

	if (is_valid_ether_addr(addr)) {
		memcpy(&ndev->dev_addr[0], addr, 6); //eth_hw_addr_set(ndev, addr);
		return;
	}

	eth_hw_addr_random(ndev);
	dev_dbg(&db->spidev->dev, "Use random MAC address\n");
}

/* set mac permanently
 */
static void dm_set_mac_lock(struct board_info *db)
{
	struct net_device *ndev = db->ndev;
	int i, oft;

	netdev_dbg(ndev, "set_mac_address %pM\n", ndev->dev_addr);

	/* write to net device and chip */
	mutex_lock(&db->addr_lock);
	for (i = 0, oft = DM9051_PAR; i < ETH_ALEN; i++, oft++)
		iow(db, oft, ndev->dev_addr[i]);
	mutex_unlock(&db->addr_lock);

	/* write to EEPROM */
	for (i = 0; i < ETH_ALEN; i += 2)
		dm_write_eeprom_func(db, i / 2, (u8 *)&ndev->dev_addr[i]);
}

/* netdev-ops
 */
static const struct of_device_id dm9051_match_table[] = {
	{ .compatible = "davicom,dm9051", },
	{},
};

static const struct spi_device_id dm9051_id_table[] = {
	{ "dm9051", 0 },
	{},
};

static const struct net_device_ops dm9051_netdev_ops = {
	.ndo_open = dm9051_open,
	.ndo_stop = dm9051_stop,
	.ndo_start_xmit = dm9051_start_xmit,
	.ndo_set_rx_mode = dm9051_set_multicast_list_schedule,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = dm9051_set_mac_address,
};

/* ethtool-ops
 */
static void
dm9051_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strscpy(info->driver, DRVNAME_9051, sizeof(info->driver));
}

static void dm9051_set_msglevel(struct net_device *dev, u32 value)
{
	struct board_info *dm = to_dm9051_board(dev);

	dm->msg_enable = value;
}

static u32 dm9051_get_msglevel(struct net_device *dev)
{
	struct board_info *dm = to_dm9051_board(dev);

	return dm->msg_enable;
}

static int dm9051_get_link_ksettings(struct net_device *dev,
				     struct ethtool_link_ksettings *cmd)
{
	struct board_info *dm = to_dm9051_board(dev);

	mii_ethtool_get_link_ksettings(&dm->mii, cmd);
	return 0;
}

static int dm9051_set_link_ksettings(struct net_device *dev,
				     const struct ethtool_link_ksettings *cmd)
{
	struct board_info *dm = to_dm9051_board(dev);

	return mii_ethtool_set_link_ksettings(&dm->mii, cmd);
}

static int dm9051_nway_reset(struct net_device *dev)
{
	struct board_info *dm = to_dm9051_board(dev);

	return mii_nway_restart(&dm->mii);
}

static u32 dm9051_get_link(struct net_device *dev)
{
	struct board_info *db = to_dm9051_board(dev);

	return mii_link_ok(&db->mii);
}

static int dm9051_get_eeprom_len(struct net_device *dev)
{
	return 128;
}

static int dm9051_get_eeprom(struct net_device *dev,
			     struct ethtool_eeprom *ee, u8 *data)
{
	struct board_info *dm = to_dm9051_board(dev);
	int offset = ee->offset;
	int len = ee->len;
	int i;

	if ((len & 1) != 0 || (offset & 1) != 0)
		return -EINVAL;

	ee->magic = DM_EEPROM_MAGIC;

	for (i = 0; i < len; i += 2)
		dm_read_eeprom_func(dm, (offset + i) / 2, data + i);
	return 0;
}

static int dm9051_set_eeprom(struct net_device *dev,
			     struct ethtool_eeprom *ee, u8 *data)
{
	struct board_info *dm = to_dm9051_board(dev);
	int offset = ee->offset;
	int len = ee->len;
	int i;

	if ((len & 1) != 0 || (offset & 1) != 0)
		return -EINVAL;

	if (ee->magic != DM_EEPROM_MAGIC)
		return -EINVAL;

	for (i = 0; i < len; i += 2)
		dm_write_eeprom_func(dm, (offset + i) / 2, data + i);
	return 0;
}

static const struct ethtool_ops dm9051_ethtool_ops = {
	.get_drvinfo = dm9051_get_drvinfo,
	.get_link_ksettings = dm9051_get_link_ksettings,
	.set_link_ksettings = dm9051_set_link_ksettings,
	.get_msglevel = dm9051_get_msglevel,
	.set_msglevel = dm9051_set_msglevel,
	.nway_reset = dm9051_nway_reset,
	.get_link = dm9051_get_link,
	.get_eeprom_len = dm9051_get_eeprom_len,
	.get_eeprom = dm9051_get_eeprom,
	.set_eeprom = dm9051_set_eeprom,
};

static void dm_operation_clear(struct board_info *db)
{
	db->bc.mac_ovrsft_counter = 0;
	db->bc.large_err_counter = 0;
	db->bc.DO_FIFO_RST_counter = 0;
}

/* reset and increase the RST counter
 */
static void dm9051_fifo_reset(u8 state, u8 *hstr, struct board_info *db)
{
	db->bc.DO_FIFO_RST_counter++;
	dm9051_reset(db);
}

static void dm9051_reset_dm9051(struct board_info *db, int rxlen)
{
	struct net_device *ndev = db->ndev;
	char *sbuff = (char *)db->prxhdr;
	char hstr[72];

	netdev_dbg(ndev, "dm9-pkt-Wrong RxLen over-range (%x= %d > %x= %d)\n",
		   rxlen, rxlen, DM9051_PKT_MAX, DM9051_PKT_MAX);

	db->bc.large_err_counter++;
	db->bc.mac_ovrsft_counter++;
	dm9051_fifo_reset(11, hstr, db);
	sprintf(hstr, "dmfifo_reset( 11 RxLenErr ) rxhdr %02x %02x %02x %02x (quick)",
		sbuff[0], sbuff[1], sbuff[2], sbuff[3]);
	netdev_dbg(ndev, "%s\n", hstr);
	netdev_dbg(ndev, " RxLenErr&MacOvrSft_Er %d, RST_c %d\n",
		   db->bc.mac_ovrsft_counter, db->bc.DO_FIFO_RST_counter);
}

/* loop rx
 */
static int dm9051_lrx(struct board_info *db)
{
	struct net_device *ndev = db->ndev;
	u8 rxbyte;
	int rxlen;
	char sbuff[DM_RXHDR_SIZE];
	struct sk_buff *skb;
	u8 *rdptr;
	int scanrr = 0;

	while (1) {
		rxbyte = ior(db, DM_SPI_MRCMDX); /* Dummy read */
		rxbyte = ior(db, DM_SPI_MRCMDX); /* Dummy read */
		if (rxbyte != DM9051_PKT_RDY) {
			isr_reg_clear_to_stop_mrcmd(db);
			break; /* exhaust-empty */
		}
		dm9inblk(db, sbuff, DM_RXHDR_SIZE);
		isr_reg_clear_to_stop_mrcmd(db);

		db->prxhdr = (struct dm9051_rxhdr *)sbuff;
		if (db->prxhdr->rxstatus & 0xbf) {
			netdev_dbg(ndev, "warn : rxhdr.status 0x%02x\n",
				   db->prxhdr->rxstatus);
		}
		if (db->prxhdr->rxlen > DM9051_PKT_MAX) {
			dm9051_reset_dm9051(db, rxlen);
			return scanrr;
		}

		rxlen = db->prxhdr->rxlen;
		skb = dev_alloc_skb(rxlen + 4);
		if (!skb) {
			netdev_dbg(ndev, "alloc skb size %d fail\n", rxlen + 4);
			return scanrr;
		}
		skb_reserve(skb, 2);
		rdptr = (u8 *)skb_put(skb, rxlen - 4);

		dm9inblk(db, rdptr, rxlen);
		isr_reg_clear_to_stop_mrcmd(db);

		skb->protocol = eth_type_trans(skb, db->ndev);
		if (db->ndev->features & NETIF_F_RXCSUM)
			skb_checksum_none_assert(skb);
		if (in_interrupt())
			netif_rx(skb);
		else
			netif_rx_ni(skb);
		db->ndev->stats.rx_bytes += rxlen;
		db->ndev->stats.rx_packets++;
		scanrr++;
	}
	return scanrr;
}

/* single tx
 */
static int dm9051_stx(struct board_info *db, u8 *buff, unsigned int len)
{
	int ret;
	u8 check_val;

	/* shorter waiting time with tx-end check */
	ret = read_poll_timeout(ior, check_val, check_val & (NSR_TX2END | NSR_TX1END),
				1, 20, false, db, DM9051_NSR);
	dm9outblk(db, buff, len);
	iow(db, DM9051_TXPLL, len);
	iow(db, DM9051_TXPLH, len >> 8);
	iow(db, DM9051_TCR, TCR_TXREQ);
	return ret;
}

static int dm9051_send(struct board_info *db)
{
	struct net_device *ndev = db->ndev;
	int ntx = 0;

	while (!skb_queue_empty(&db->txq)) {
		struct sk_buff *skb;

		skb = dm_sk_buff_get(db);
		if (skb) {
			ntx++;
			if (dm9051_stx(db, skb->data, skb->len))
				netdev_dbg(ndev, "timeout %d--- WARNING---do-ntx\n", ntx);
			ndev->stats.tx_bytes += skb->len;
			ndev->stats.tx_packets++;
			dev_kfree_skb(skb);
		}
	}
	return ntx;
}

/* end with enable the interrupt mask
 */
static irqreturn_t dm9051_rx_threaded_irq(int irq, void *pw)
{
	struct board_info *db = pw;
	int nrx;

	mutex_lock(&db->spi_lock); /* dlywork essential */
	dm_imr_disable_lock_essential(db); /* set imr disable */
	if (netif_carrier_ok(db->ndev)) {
		mutex_lock(&db->addr_lock);
		do {
			nrx = dm9051_lrx(db);
			dm9051_send(db); /* for more performance */
		} while (nrx);
		mutex_unlock(&db->addr_lock);
	}
	dm_imr_enable_lock_essential(db); /* set imr enable */
	mutex_unlock(&db->spi_lock); /* dlywork essential */
	return IRQ_HANDLED;
}

/* end with enable the interrupt mask
 */
static int dm_opencode_receiving(struct net_device *ndev, struct board_info *db)
{
	int ret;
	struct spi_device *spi = db->spidev;

	ndev->irq = spi->irq; /* by dts */
	ret = request_threaded_irq(spi->irq, NULL, dm9051_rx_threaded_irq,
				   IRQF_TRIGGER_LOW | IRQF_ONESHOT,
				   ndev->name, db);
	if (ret < 0) {
		netdev_err(ndev, "failed to get irq\n");
		return ret;
	}
	dm_imr_enable_lock_essential(db);
	netdev_info(ndev, "[dm_open] %pM irq_no %d ACTIVE_LOW\n", ndev->dev_addr, ndev->irq);

#if POLL_LINK
	dm_carrier_off(ndev);
	db->print_status.old_carrier = 
	db->print_status.new_carrier = netif_carrier_ok(ndev); //db->ndev
	printk("[phy_open old_carri, new_carri: %d, %d]\n", db->print_status.old_carrier, db->print_status.new_carrier);
#endif
	schedule_delayed_work(&db->phy_poll, HZ * 1); /* sched_start */
	return 0;
}

static void int_tx_delay(struct work_struct *w)
{
	struct delayed_work *dw = to_delayed_work(w);
	struct board_info *db = container_of(dw, struct board_info, tx_work);

	mutex_lock(&db->spi_lock); /* dlywork essential */
	mutex_lock(&db->addr_lock);
	dm9051_send(db);
	mutex_unlock(&db->addr_lock);
	mutex_unlock(&db->spi_lock); /* dlywork essential */
}

static void int_rxctl_delay(struct work_struct *w)
{
	struct delayed_work *dw = to_delayed_work(w);
	struct board_info *db = container_of(dw, struct board_info, rxctrl_work);
	struct net_device *ndev = db->ndev;
	int i, oft;

	mutex_lock(&db->addr_lock);

	for (i = 0, oft = DM9051_PAR; i < ETH_ALEN; i++, oft++)
		iow(db, oft, ndev->dev_addr[i]);

	/* Write the hash table */
	for (i = 0, oft = DM9051_MAR; i < 4; i++) {
		iow(db, oft++, db->hash_table[i]);
		iow(db, oft++, db->hash_table[i] >> 8);
	}

	rcr_reg_start(db, db->rcr_all);

	mutex_unlock(&db->addr_lock);
}

static void int_phy_poll(struct work_struct *w)
{
	struct delayed_work *dw = to_delayed_work(w);
	struct board_info *db = container_of(dw, struct board_info, phy_poll);

	dm_carrier_poll(db);
#if POLL_LINK
	db->print_status.new_carrier = netif_carrier_ok(db->ndev);

	if (db->print_status.new_carrier != db->print_status.old_carrier) {
		printk("[phy_poll old_carri, new_carri: %d, %d]\n", db->print_status.old_carrier, db->print_status.new_carrier);
		printk(db->print_status.new_carrier ? "[dm9] Link-up\n" : "[dm9] Link-down\n");
		db->print_status.old_carrier = db->print_status.new_carrier;
		//.return true;
	}
#endif
	schedule_delayed_work(&db->phy_poll, HZ * 1);
}

/* Irq free and schedule delays cancel
 */
static void dm_stopcode_release(struct board_info *db)
{
	free_irq(db->spidev->irq, db);
	cancel_delayed_work_sync(&db->phy_poll);
	cancel_delayed_work_sync(&db->rxctrl_work);
	cancel_delayed_work_sync(&db->tx_work);
}

static void dm_control_init(struct board_info *db)
{
	mutex_init(&db->spi_lock);
	mutex_init(&db->addr_lock);
	INIT_DELAYED_WORK(&db->phy_poll, int_phy_poll);
	INIT_DELAYED_WORK(&db->rxctrl_work, int_rxctl_delay);
	INIT_DELAYED_WORK(&db->tx_work, int_tx_delay);
}

static void dm9051_init_dm9051(struct net_device *dev)
{
	struct board_info *db = netdev_priv(dev);

	dm9051_fifo_reset(1, NULL, db);
	imr_reg_stop(db);
}

static void dm_opencode_lock(struct net_device *dev, struct board_info *db)
{
	mutex_lock(&db->addr_lock); /* Note: must */
	iow(db, DM9051_GPR, 0); /* Reg 1F is not set by reset, REG_1F bit0 activate phyxcer */
	mdelay(1); /* delay needs for activate phyxcer */
	db->imr_all = IMR_PAR | IMR_PRM;
	db->rcr_all = RCR_DIS_LONG | RCR_DIS_CRC | RCR_RXEN;
	db->lcr_all = LMCR_MODE1;
	dm9051_init_dm9051(dev);
	mutex_unlock(&db->addr_lock);
}

static void dm_stopcode_lock(struct board_info *db)
{
	mutex_lock(&db->addr_lock);
	dm_phy_write_func(db, MII_BMCR, BMCR_RESET); /* PHY RESET */
	iow(db, DM9051_GPR, 0x01); /* Power-Down PHY */
	rcr_reg_stop(db); /* Disable RX */
	mutex_unlock(&db->addr_lock);
}

static void dm_opencode_net(struct net_device *ndev, struct board_info *db)
{
	dm_sk_buff_head_init(db);
	netif_start_queue(ndev);
	netif_wake_queue(ndev);
	dm_carrier_init(db);
}

static void dm_stopcode_net(struct net_device *ndev)
{
	netif_stop_queue(ndev);
	dm_carrier_off(ndev);
}

/* Open network device
 * Called when the network device is marked active, such as a user executing
 * 'ifconfig up' on the device.
 */
static int dm9051_open(struct net_device *ndev)
{
	struct board_info *db = netdev_priv(ndev);

	dm_opencode_lock(ndev, db);
	dm_opencode_net(ndev, db);
	return dm_opencode_receiving(ndev, db);
}

/* Close network device
 * Called to close down a network device which has been active. Cancell any
 * work, shutdown the RX and TX process and then place the chip into a low
 * power state while it is not being used.
 */
static int dm9051_stop(struct net_device *ndev)
{
	struct board_info *db = netdev_priv(ndev);

	dm_stopcode_release(db);
	dm_stopcode_net(ndev);
	dm_stopcode_lock(db);
	return 0;
}

/* event: play a schedule starter in condition
 */
static netdev_tx_t dm9051_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct board_info *db = netdev_priv(dev);

	dm_sk_buff_set(db, skb); /* add to skb */
	schedule_delayed_work(&db->tx_work, 0);
	return NETDEV_TX_OK;
}

/* event: play with a schedule starter
 */
static void dm9051_set_multicast_list_schedule(struct net_device *ndev)
{
	struct board_info *db = netdev_priv(ndev);
	u8 rcr = RCR_DIS_LONG | RCR_DIS_CRC | RCR_RXEN;
	struct netdev_hw_addr *ha;
	u32 hash_val;

	/* rxctl */
	if (ndev->flags & IFF_PROMISC) {
		rcr |= RCR_PRMSC;
		netdev_dbg(ndev, "set_multicast rcr |= RCR_PRMSC, rcr= %02x\n", rcr);
	}

	if (ndev->flags & IFF_ALLMULTI) {
		rcr |= RCR_ALL;
		netdev_dbg(ndev, "set_multicast rcr |= RCR_ALLMULTI, rcr= %02x\n", rcr);
	}

	db->rcr_all = rcr;

	/* broadcast address */
	db->hash_table[0] = 0;
	db->hash_table[1] = 0;
	db->hash_table[2] = 0;
	db->hash_table[3] = 0x8000;

	/* the multicast address in Hash Table : 64 bits */
	netdev_for_each_mc_addr(ha, ndev) {
		hash_val = ether_crc_le(6, ha->addr) & 0x3f;
		db->hash_table[hash_val / 16] |= (u16)1 << (hash_val % 16);
	}

	schedule_delayed_work(&db->rxctrl_work, 0);
}

/* event: NOT play with a schedule starter! will iow() directly.
 */
static int dm9051_set_mac_address(struct net_device *ndev, void *p)
{
	struct board_info *db = netdev_priv(ndev);
	int ret = eth_mac_addr(ndev, p);

	if (ret < 0)
		return ret;

	dm_set_mac_lock(db);
	return 0;
}

/* probe subs
 */
static void dm_netdev_and_db(struct net_device *ndev, struct board_info *db)
{
	ndev->mtu = 1500;
	ndev->if_port = IF_PORT_100BASET;
	ndev->netdev_ops = &dm9051_netdev_ops;
	ndev->ethtool_ops = &dm9051_ethtool_ops;
	db->mii.dev = ndev;
	db->mii.phy_id = 1;
	db->mii.phy_id_mask = 1;
	db->mii.reg_num_mask = 0x1f;
	db->mii.mdio_read = dm9051_phy_read_lock;
	db->mii.mdio_write = dm9051_phy_write_lock;
}

static void dm_spimsg_addtail(struct board_info *db)
{
	memset(&db->spi_xfer2, 0, sizeof(struct spi_transfer) * 2);
	spi_message_init(&db->spi_msg2);
	spi_message_add_tail(&db->spi_xfer2[0], &db->spi_msg2);
	spi_message_add_tail(&db->spi_xfer2[1], &db->spi_msg2);
}

static int dm_chipid_detect(struct board_info *db)
{
	if (dm9051_chipid(db) == DM9051_ID)
		return 0;
	return -ENODEV;
}

static int dm9051_hw_reset(struct device *dev, struct board_info *db)
{
	struct gpio_config config;
	int ret;

	db->reset_gpio = of_get_named_gpio_flags(dev->of_node, "reset-gpios", 0,
			(enum of_gpio_flags *)&config);

	if (db->reset_gpio < 0) {
		pr_err("%s fail to get reset-gpios pin from dts!\n", __func__);
		return -1;
	} else {
		pr_info("%s reset_gpio = %d!\n", __func__, db->reset_gpio);
	}

	ret = devm_gpio_request_one(dev, db->reset_gpio, GPIOF_OUT_INIT_HIGH, "dm9051-reset-gpio");
	if (ret < 0)
		return -1;

	gpio_direction_output(db->reset_gpio, GPIOF_OUT_INIT_LOW);
	mdelay(1);
	gpio_direction_output(db->reset_gpio, GPIOF_OUT_INIT_HIGH);
	mdelay(1);

	pr_info("%s - done !\n", __func__);
	return 0;
}

static int dm9051_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct net_device *ndev;
	struct board_info *db;
	int ret = 0;

//	dm9051_hw_reset(dev);

	ndev = alloc_etherdev(sizeof(struct board_info));
	if (!ndev)
		return -ENOMEM;
	SET_NETDEV_DEV(ndev, dev);
	dev_set_drvdata(dev, ndev);
	db = netdev_priv(ndev);
	memset(db, 0, sizeof(struct board_info));
	db->msg_enable = 0;
	db->spidev = spi;
	db->ndev = ndev;
	dm_netdev_and_db(ndev, db);

	dm9051_hw_reset(dev, db);

	dm_spimsg_addtail(db);
	dm_control_init(db); /* init_delayed_works */
	ret = dm_chipid_detect(db);
	if (ret) {
		dev_err(dev, "chip id error\n");
		goto err_netdev;
	}
	dm9051_read_mac_to_dev(ndev, db);
	ret = register_netdev(ndev);
	if (ret) {
		dev_err(dev, "failed to register network device\n");
		goto err_netdev;
	}
	dm_operation_clear(db);
	dm_carrier_off(ndev);
	return 0;
err_netdev:
	free_netdev(ndev);
	return ret;
}

static int dm9051_all_stop(struct board_info *db) {
	dm_stopcode_lock(db);
	return 0;
}

static int
dm9051_drv_suspend(struct device *dev)
{
	struct net_device *ndev = dev_get_drvdata(dev);
	struct board_info *db = netdev_priv(ndev);

	printk("=====> +++ [%s] start !\n",__func__);
	if (ndev) {
		db = netdev_priv(ndev);
		db->in_suspend = 1;

		if (!netif_running(ndev))
		{
			gpio_set_value(db->reset_gpio, 0);
			return 0;
		}

		netif_device_detach(ndev);
		dm9051_all_stop(db);
#if 0
		/* only shutdown if not using WoL */
		if (!db->wake_state)
			dm9000_shutdown(ndev);
#endif
	}

	gpio_set_value(db->reset_gpio, 0);
	printk("=====> --- [%s] end !\n",__func__);
	return 0;
}

static int dm9051_all_start(struct board_info *db) {
	dm_opencode_lock(db->ndev, db);
	dm_imr_enable_lock_essential(db);
	return 0;
}

static int
dm9051_drv_resume(struct device *dev)
{
	struct net_device *ndev = dev_get_drvdata(dev);
	struct board_info *db = netdev_priv(ndev);

	printk("=====> +++ [%s] start !\n",__func__);
	gpio_set_value(db->reset_gpio, 1);

	if (ndev) {
		if (netif_running(ndev)) {
#if 0
			/* reset if we were not in wake mode to ensure if
			 * the device was powered off it is in a known state */
			if (!db->wake_state) {
				dm9000_init_dm9000(ndev);
				dm9000_unmask_interrupts(db);
			}
#endif
            dm9051_all_start(db);
			netif_device_attach(ndev);
		}

		db->in_suspend = 0;
	}

	printk("=====> --- [%s] end !\n",__func__);
	return 0;
}

static const struct dev_pm_ops dm9051_drv_pm_ops = {
	.suspend	= dm9051_drv_suspend,
	.resume		= dm9051_drv_resume,
};

static int dm9051_drv_remove(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct net_device *ndev = dev_get_drvdata(dev);
	struct board_info *db = netdev_priv(ndev);

	unregister_netdev(db->ndev);
	free_netdev(db->ndev);
	return 0;
}

static struct spi_driver dm9051_driver = {
	.driver = {
		.name = DRVNAME_9051,
		.pm = &dm9051_drv_pm_ops,
		.of_match_table = dm9051_match_table,
	},
	.probe = dm9051_probe,
	.remove = dm9051_drv_remove,
	.id_table = dm9051_id_table,
};
module_spi_driver(dm9051_driver);

MODULE_AUTHOR("Joseph CHANG <joseph_chang@davicom.com.tw>");
MODULE_DESCRIPTION("Davicom DM9051 network SPI driver");
MODULE_LICENSE("GPL");
