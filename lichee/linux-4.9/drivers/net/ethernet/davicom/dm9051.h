/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021 Davicom Semiconductor,Inc.
 * Davicom DM9051 SPI Fast Ethernet Linux driver
 */

#ifndef _DM9051_H_
#define _DM9051_H_

#define DRVNAME_9051		"dm9051"

#define DM9051_ID		0x9051

#define DM9051_NCR		0x00
#define DM9051_NSR		0x01
#define DM9051_TCR		0x02
#define DM9051_RCR		0x05
#define DM9051_BPTR		0x08
#define DM9051_FCR		0x0A
#define DM9051_EPCR		0x0B
#define DM9051_EPAR		0x0C
#define DM9051_EPDRL		0x0D
#define DM9051_EPDRH		0x0E
#define DM9051_PAR		0x10
#define DM9051_MAR		0x16
#define DM9051_GPCR		0x1E
#define DM9051_GPR		0x1F

#define DM9051_PIDL		0x2A
#define DM9051_PIDH		0x2B
#define DM9051_SMCR		0x2F
#define	DM9051_ATCR		0x30
#define	DM9051_SPIBCR		0x38
#define DM9051_INTCR		0x39
#define DM9051_PPCR		0x3D

#define DM9051_MPCR		0x55
#define DM9051_LMCR		0x57
#define DM9051_MBNDRY		0x5E

#define DM9051_MRRL		0x74
#define DM9051_MRRH		0x75
#define DM9051_MWRL		0x7A
#define DM9051_MWRH		0x7B
#define DM9051_TXPLL		0x7C
#define DM9051_TXPLH		0x7D
#define DM9051_ISR		0x7E
#define DM9051_IMR		0x7F

#define DM_SPI_MRCMDX		(0x70)
#define DM_SPI_MRCMD		(0x72)
#define DM_SPI_MWCMD		(0x78)

#define DM_SPI_RD		(0x00)
#define DM_SPI_WR		(0x80)

/* dm9051 Ethernet
 */
//0x00
#define NCR_WAKEEN		BIT(6)
#define NCR_FDX			BIT(3)
#define NCR_RST			BIT(0)
//0x02
#define TCR_DIS_JABBER_TIMER	BIT(6) /* for Jabber Packet support */
#define TCR_TXREQ		BIT(0)
//0x01
#define NSR_SPEED		BIT(7)
#define NSR_LINKST		BIT(6)
#define NSR_WAKEST		BIT(5)
#define NSR_TX2END		BIT(3)
#define NSR_TX1END		BIT(2)
//0x05
#define RCR_DIS_WATCHDOG_TIMER	BIT(6)  /* for Jabber Packet support */
#define RCR_DIS_LONG		BIT(5)
#define RCR_DIS_CRC		BIT(4)
#define RCR_ALL			BIT(3)
#define RCR_PRMSC		BIT(1)
#define RCR_RXEN		BIT(0)
#define RCR_RX_DISABLE		(RCR_DIS_LONG | RCR_DIS_CRC)
//0x06
#define RSR_RF			BIT(7)
#define RSR_MF			BIT(6)
#define RSR_LCS			BIT(5)
#define RSR_RWTO		BIT(4)
#define RSR_PLE			BIT(3)
#define RSR_AE			BIT(2)
#define RSR_CE			BIT(1)
#define RSR_FOE			BIT(0)
//0x0A
#define FCR_TXPEN		BIT(5)
#define FCR_BKPM		BIT(3)
#define FCR_FLCE		BIT(0)
#define FCR_FLOW_ENABLE		(FCR_TXPEN | FCR_BKPM | FCR_FLCE)
//0x0B
#define EPCR_WEP		BIT(4)
#define EPCR_EPOS		BIT(3)
#define EPCR_ERPRR		BIT(2)
#define EPCR_ERPRW		BIT(1)
#define EPCR_ERRE		BIT(0)
//0x1E
#define GPCR_GEP_CNTL		BIT(0)
//0x30
#define	ATCR_AUTO_TX		BIT(7)
//0x39
#define INTCR_POL_LOW		BIT(0)
#define INTCR_POL_HIGH		(0 << 0)
//0x3D
// Pause Packet Control Register - default = 1
#define PPCR_PAUSE_COUNT	0x08
//0x55
#define MPCR_RSTTX		BIT(1)
#define MPCR_RSTRX		BIT(0)
//0x57
// LEDMode Control Register - LEDMode1
// Value 0x81 : bit[7] = 1, bit[2] = 0, bit[1:0] = 01b
#define LMCR_NEWMOD		BIT(7)
#define LMCR_TYPED1		BIT(1)
#define LMCR_TYPED0		BIT(0)
#define LMCR_MODE1		(LMCR_NEWMOD | LMCR_TYPED0)
//0x5E
#define MBNDRY_BYTE		BIT(7)
//0xFE
#define ISR_MBS			BIT(7)
#define ISR_ROOS		BIT(3)
#define ISR_ROS			BIT(2)
#define ISR_PTS			BIT(1)
#define ISR_PRS			BIT(0)
#define ISR_CLR_STATUS		(ISR_ROOS | ISR_ROS | ISR_PTS | ISR_PRS)
//0xFF
#define IMR_PAR			BIT(7)
#define IMR_LNKCHGI		BIT(5)
#define IMR_PTM			BIT(1)
#define IMR_PRM			BIT(0)

/* Const
 */
#define DM9051_PHY		0x40	/* PHY address 0x01 */
#define DM9051_PKT_RDY		0x01	/* Packet ready to receive */
#define DM9051_PKT_MAX		1536	/* Received packet max size */
#define DM_EEPROM_MAGIC		(0x9051)

/* netdev_ops
 */
static int dm9051_open(struct net_device *dev);
static int dm9051_stop(struct net_device *dev);
static netdev_tx_t dm9051_start_xmit(struct sk_buff *skb, struct net_device *dev);
static void dm9051_set_multicast_list_schedule(struct net_device *dev);
static int dm9051_set_mac_address(struct net_device *dev, void *p);

static inline struct board_info *to_dm9051_board(struct net_device *dev)
{
	return netdev_priv(dev);
}

/* carrier
 */
#define	dm_carrier_init(db)			mii_check_link(&(db)->mii)
#define	dm_carrier_poll(db)			mii_check_link(&(db)->mii)
#define	dm_carrier_off(dev)			netif_carrier_off(dev)

/* xmit support
 */
#define	dm_sk_buff_head_init(db)		skb_queue_head_init(&(db)->txq)
#define	dm_sk_buff_get(db)			skb_dequeue(&(db)->txq)
#define	dm_sk_buff_set(db, skb)			skb_queue_tail(&(db)->txq, skb)

/* spi transfers
 */
#define ior					std_spi_read_reg			// read reg
#define iior					disp_spi_read_reg			// read disp
#define iow					std_spi_write_reg			// write reg
#define dm9inblk				std_read_rx_buf_ncpy			// read buff
#define dm9outblk				std_write_tx_buf			// write buf

#define	ncr_reg_reset(db)			iow(db, DM9051_NCR, NCR_RST)		// reset
#define	mbd_reg_byte(db)			iow(db, DM9051_MBNDRY, MBNDRY_BYTE)	// MemBound
#define	fcr_reg_enable(db)			iow(db, DM9051_FCR, FCR_FLOW_ENABLE)	// FlowCtrl
#define	ppcr_reg_seeting(db)			iow(db, DM9051_PPCR, PPCR_PAUSE_COUNT)	// PauPktCn
#define	isr_reg_clear_to_stop_mrcmd(db)		iow(db, DM9051_ISR, 0xff)		// ClearISR
#define rcr_reg_stop(db)			iow(db, DM9051_RCR, RCR_RX_DISABLE)	// DisabRX
#define imr_reg_stop(db)			iow(db, DM9051_IMR, IMR_PAR)		// DisabAll
#define rcr_reg_start(db, rcr_all)		iow(db, DM9051_RCR, rcr_all)		// EnabRX
#define imr_reg_start(db, imr_all)		iow(db, DM9051_IMR, imr_all)		// Re-enab
#define	intcr_reg_setval(db)			iow(db, DM9051_INTCR, INTCR_POL_LOW)	// INTCR
#define	ledcr_reg_setting(db, lcr_all)		iow(db, DM9051_LMCR, lcr_all)		// LEDMode1

/* structure definitions
 */
struct rx_ctl_mach {
	u16				large_err_counter;  /* The error of 'Large Err' */
	u16				mac_ovrsft_counter;  /* The error of 'MacOvrSft_Er' */
	u16				DO_FIFO_RST_counter; /* The counter of 'fifo_reset' */
};

struct dm9051_rxhdr {
	u8				rxpktready;
	u8				rxstatus;
	__le16				rxlen;
};

#define NEW_KT515	0 //while nwe kernel 515, use spi_write().
#define POLL_LINK	1
#if POLL_LINK
typedef struct dm_print_phy {
	bool old_carrier;
	bool new_carrier;
} dm_print_phy_t;
#endif

struct board_info {
	u8				cmd[2] ____cacheline_aligned;
	struct spi_transfer		spi_xfer2[2] ____cacheline_aligned;
	struct spi_message		spi_msg2 ____cacheline_aligned;
	struct rx_ctl_mach		bc ____cacheline_aligned;
	struct dm9051_rxhdr		*prxhdr ____cacheline_aligned;
	struct spi_device		*spidev;
	struct net_device		*ndev;
	struct mii_if_info		mii;
	struct sk_buff_head		txq;
	struct mutex			spi_lock;	// delayed_work's lock
	struct mutex			addr_lock;	// dm9051's REG lock
	struct delayed_work		phy_poll;
	struct delayed_work		rxctrl_work;
	struct delayed_work		tx_work;
	u16				hash_table[4];
	u32				msg_enable ____cacheline_aligned;
	u8				imr_all;
	u8				rcr_all;
	u8				lcr_all;
#if POLL_LINK
	dm_print_phy_t			print_status;
#endif
#if NEW_KT515
	char				spi_trans_buf[1600] ____cacheline_aligned;
#endif
};

#define	DM_RXHDR_SIZE			sizeof(struct dm9051_rxhdr)

#endif /* _DM9051_H_ */
