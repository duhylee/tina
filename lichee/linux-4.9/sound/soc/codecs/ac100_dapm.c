/*
 * sound\soc\codec\ac100_dapm.c
 * (C) Copyright 2010-2017
 * Reuuimlla Technology Co., Ltd. <www.reuuimllatech.com>
 * huangxin <huangxin@Reuuimllatech.com>
 *
 * some simple description for this code
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/tlv.h>
#include <linux/io.h>
#include <linux/regulator/consumer.h>
#include <linux/i2c.h>
#include <linux/irq.h>
#include <linux/input.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <sound/jack.h>
#include <linux/workqueue.h>
#include <linux/clk.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>

#include <linux/sunxi-gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/mfd/ac100-mfd.h>

#include "ac100.h"

/* key define */
#define KEY_HEADSETHOOK         (226)
#define HEADSET_CHECKCOUNT		(10)
#define HEADSET_CHECKCOUNT_SUM	(2)

struct spk_gpio spkgpio;
struct spk_gpio hsgpio;
static int speaker_double_used;
static int double_speaker_val;
static int single_speaker_val;
static int headset_val;
static int earpiece_val;
static int mainmic_val;
static int headsetmic_val;
static int dmic_used;
static int adc_digital_val;
static int agc_used;
static int drc_used;
static int aif2_lrck_div;
static int aif2_bclk_div;
static volatile int reset_flag;

struct val_str {
	int *val;
	char *str;
};

enum dectect_jack {
	PLUG_OUT = 0x0,
	PLUG_IN  = 0x1,
};

static struct val_str properties[] = {
	{&speaker_double_used, "speaker_double_used"},
	{&double_speaker_val, "double_speaker_val"},
	{&single_speaker_val, "single_speaker_val"},
	{&headset_val, "headset_val"},
	{&earpiece_val, "earpiece_val"},
	{&mainmic_val, "mainmic_val"},
	{&headsetmic_val, "headsetmic_val"},
	{&dmic_used, "dmic_used"},
	{&adc_digital_val, "adc_digital_val"},
	{&agc_used, "agc_used"},
	{&drc_used, "drc_used"}
};

#define ac100_RATES  (SNDRV_PCM_RATE_8000_192000|SNDRV_PCM_RATE_KNOT)
#define ac100_FORMATS (SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE | \
	SNDRV_PCM_FMTBIT_S18_3LE | \
	SNDRV_PCM_FMTBIT_S20_3LE | \
	SNDRV_PCM_FMTBIT_S24_LE | \
	SNDRV_PCM_FMTBIT_S32_LE)

struct voltage_supply {
	struct regulator *avcc;
	struct regulator *io1;
	struct regulator *io2;
	struct regulator *ldoin;
	struct regulator *cpvdd;
};

/*struct for ac100*/
struct ac100_priv {
	struct ac100 *ac100;
	struct snd_soc_codec *codec;

	struct mutex dac_mutex;
	struct mutex adc_mutex;
	struct mutex mute_mutex;
	u8 dac_enable;
	u8 adc_enable;
	struct mutex aifclk_mutex;
	u8 aif1_clken;
	u8 aif2_clken;
	u8 aif3_clken;

	u8 aif2_mute;
	u8 aif1_mute;

	/*voltage supply*/
	struct voltage_supply vol_supply;

	/*headset*/
	int state;
	int check_count;
	int check_count_sum;

	struct work_struct codec_resume;

	struct delayed_work hs_detect_work;
	struct delayed_work hs_irq_work;
	struct mutex jack_mutex;
	struct snd_soc_jack jack;
	u32 detect_state;
	u32 jack_irq;		/*switch irq*/
	u32 HEADSET_DATA;	/*threshod for switch insert*/
	u32 switch_status;
	u32 key_volup;
	u32 key_voldown;
	u32 key_hook;
	u32 jack_gpio;
	bool hmic_used;
};
#if 0
static void snd_sunxi_unregister_jack(struct ac100_priv *ac100)
{
	/*
	*Set process button events to false so that the
	*delayed work will not be scheduled.
	*/
	cancel_delayed_work_sync(&ac100->hs_detect_work);
	cancel_delayed_work_sync(&ac100->hs_irq_work);
}
#endif
static void get_configuration(struct platform_device *pdev)
{
	struct device_node *node = of_find_compatible_node(NULL, NULL, "allwinner,sunxi-ac100-codec");
	unsigned int val;
	int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(properties); i++) {
		ret = of_property_read_u32(node, properties[i].str, &val);
		if (ret < 0) {
			dev_warn(&pdev->dev, "%s config missing or invalid\n",
				properties[i].str);
			*(properties[i].val) = 0;
		} else {
			*(properties[i].val) = val;
			pr_debug("%s=%d\n",
				properties[i].str, *(properties[i].val));
		}
	}
}

#if 0
static void agc_config(struct snd_soc_codec *codec)
{
	int reg_val;

	reg_val = snd_soc_read(codec, 0xb4);
	reg_val |= (0x3<<6);
	snd_soc_write(codec, 0xb4, reg_val);

	reg_val = snd_soc_read(codec, 0x84);
	reg_val &= ~(0x3f<<8);
	reg_val |= (0x31<<8);
	snd_soc_write(codec, 0x84, reg_val);

	reg_val = snd_soc_read(codec, 0x84);
	reg_val &= ~(0xff<<0);
	reg_val |= (0x28<<0);
	snd_soc_write(codec, 0x84, reg_val);

	reg_val = snd_soc_read(codec, 0x85);
	reg_val &= ~(0x3f<<8);
	reg_val |= (0x31<<8);
	snd_soc_write(codec, 0x85, reg_val);

	reg_val = snd_soc_read(codec, 0x85);
	reg_val &= ~(0xff<<0);
	reg_val |= (0x28<<0);
	snd_soc_write(codec, 0x85, reg_val);

	reg_val = snd_soc_read(codec, 0x8a);
	reg_val &= ~(0x7fff<<0);
	reg_val |= (0x24<<0);
	snd_soc_write(codec, 0x8a, reg_val);

	reg_val = snd_soc_read(codec, 0x8b);
	reg_val &= ~(0x7fff<<0);
	reg_val |= (0x2<<0);
	snd_soc_write(codec, 0x8b, reg_val);

	reg_val = snd_soc_read(codec, 0x8c);
	reg_val &= ~(0x7fff<<0);
	reg_val |= (0x24<<0);
	snd_soc_write(codec, 0x8c, reg_val);

	reg_val = snd_soc_read(codec, 0x8d);
	reg_val &= ~(0x7fff<<0);
	reg_val |= (0x2<<0);
	snd_soc_write(codec, 0x8d, reg_val);

	reg_val = snd_soc_read(codec, 0x8e);
	reg_val &= ~(0x1f<<8);
	reg_val |= (0xf<<8);
	reg_val &= ~(0x1f<<0);
	reg_val |= (0xf<<0);
	snd_soc_write(codec, 0x8e, reg_val);

	reg_val = snd_soc_read(codec, 0x93);
	reg_val &= ~(0x7ff<<0);
	reg_val |= (0xfc<<0);
	snd_soc_write(codec, 0x93, reg_val);
	snd_soc_write(codec, 0x94, 0xabb3);
}

#endif

static void drc_config(struct snd_soc_codec *codec)
{
	int reg_val;

	reg_val = snd_soc_read(codec, 0xa3);
	reg_val &= ~(0x7ff<<0);
	reg_val |= 1<<0;
	snd_soc_write(codec, 0xa3, reg_val);
	snd_soc_write(codec, 0xa4, 0x2baf);

	reg_val = snd_soc_read(codec, 0xa5);
	reg_val &= ~(0x7ff<<0);
	reg_val |= 1<<0;
	snd_soc_write(codec, 0xa5, reg_val);
	snd_soc_write(codec, 0xa6, 0x2baf);

	reg_val = snd_soc_read(codec, 0xa7);
	reg_val &= ~(0x7ff<<0);
	snd_soc_write(codec, 0xa7, reg_val);
	snd_soc_write(codec, 0xa8, 0x44a);

	reg_val = snd_soc_read(codec, 0xa9);
	reg_val &= ~(0x7ff<<0);
	snd_soc_write(codec, 0xa9, reg_val);
	snd_soc_write(codec, 0xaa, 0x1e06);

	reg_val = snd_soc_read(codec, 0xab);
	reg_val &= ~(0x7ff<<0);
	reg_val |= (0x352<<0);
	snd_soc_write(codec, 0xab, reg_val);
	snd_soc_write(codec, 0xac, 0x6910);

	reg_val = snd_soc_read(codec, 0xad);
	reg_val &= ~(0x7ff<<0);
	reg_val |= (0x77a<<0);
	snd_soc_write(codec, 0xad, reg_val);
	snd_soc_write(codec, 0xae, 0xaaaa);

	reg_val = snd_soc_read(codec, 0xaf);
	reg_val &= ~(0x7ff<<0);
	reg_val |= (0x2de<<0);
	snd_soc_write(codec, 0xaf, reg_val);
	snd_soc_write(codec, 0xb0, 0xc982);
	snd_soc_write(codec, 0x16, 0x9f9f);
}

static void agc_enable(struct snd_soc_codec *codec, bool on)
{
	int reg_val;

	if (on) {
		reg_val = snd_soc_read(codec, MOD_CLK_ENA);
		reg_val |= (0x1<<MOD_CLK_HPF_AGC);
		snd_soc_write(codec, MOD_CLK_ENA, reg_val);
		reg_val = snd_soc_read(codec, MOD_RST_CTRL);
		reg_val |= (0x1<<MOD_RESET_HPF_AGC);
		snd_soc_write(codec, MOD_RST_CTRL, reg_val);

		reg_val = snd_soc_read(codec, 0x82);
		reg_val &= ~(0xf<<0);
		reg_val |= (0x6<<0);

		reg_val &= ~(0x7<<12);
		reg_val |= (0x2<<12);
		snd_soc_write(codec, 0x82, reg_val);

		reg_val = snd_soc_read(codec, 0x83);
		reg_val &= ~(0xf<<0);
		reg_val |= (0x6<<0);

		reg_val &= ~(0x7<<12);
		reg_val |= (0x2<<12);
		snd_soc_write(codec, 0x83, reg_val);

		reg_val = snd_soc_read(codec, 0xb4);
		reg_val |= (0x3<<6);
		snd_soc_write(codec, 0xb4, reg_val);

		snd_soc_write(codec, 0x93, 0x00ef);
		snd_soc_write(codec, 0x94, 0xfac1);
	} else {
		reg_val = snd_soc_read(codec, MOD_CLK_ENA);
		reg_val &= ~(0x1<<7);
		snd_soc_write(codec, MOD_CLK_ENA, reg_val);
		reg_val = snd_soc_read(codec, MOD_RST_CTRL);
		reg_val &= ~(0x1<<7);
		snd_soc_write(codec, MOD_RST_CTRL, reg_val);

		reg_val = snd_soc_read(codec, 0x82);
		reg_val &= ~(0xf<<0);
		reg_val &= ~(0x7<<12);
		snd_soc_write(codec, 0x82, reg_val);

		reg_val = snd_soc_read(codec, 0x83);
		reg_val &= ~(0xf<<0);
		reg_val &= ~(0x7<<12);
		snd_soc_write(codec, 0x83, reg_val);
	}
}

static void drc_enable(struct snd_soc_codec *codec, bool on)
{
	int reg_val;

	if (on) {
		snd_soc_write(codec, 0xb5, 0x80);
		reg_val = snd_soc_read(codec, MOD_CLK_ENA);
		reg_val |= (0x1<<6);
		snd_soc_write(codec, MOD_CLK_ENA, reg_val);
		reg_val = snd_soc_read(codec, MOD_RST_CTRL);
		reg_val |= (0x1<<6);
		snd_soc_write(codec, MOD_RST_CTRL, reg_val);

		reg_val = snd_soc_read(codec, 0xa0);
		reg_val |= (0x7<<0);
		snd_soc_write(codec, 0xa0, reg_val);
	} else {
		snd_soc_write(codec, 0xb5, 0x0);
		reg_val = snd_soc_read(codec, MOD_CLK_ENA);
		reg_val &= ~(0x1<<6);
		snd_soc_write(codec, MOD_CLK_ENA, reg_val);
		reg_val = snd_soc_read(codec, MOD_RST_CTRL);
		reg_val &= ~(0x1<<6);
		snd_soc_write(codec, MOD_RST_CTRL, reg_val);

		reg_val = snd_soc_read(codec, 0xa0);
		reg_val &= ~(0x7<<0);
		snd_soc_write(codec, 0xa0, reg_val);
	}
}

static void set_configuration(struct snd_soc_codec *codec)
{
	if (speaker_double_used)
		snd_soc_update_bits(codec, SPKOUT_CTRL, (0x1f<<SPK_VOL),
			(double_speaker_val<<SPK_VOL));
	else
		snd_soc_update_bits(codec, SPKOUT_CTRL, (0x1f<<SPK_VOL),
			(single_speaker_val<<SPK_VOL));

	snd_soc_update_bits(codec, HPOUT_CTRL, (0x3f<<HP_VOL),
		(headset_val<<HP_VOL));
	snd_soc_update_bits(codec, ESPKOUT_CTRL, (0x1f<<ESP_VOL),
		(earpiece_val<<ESP_VOL));
	snd_soc_update_bits(codec, ADC_SRCBST_CTRL, (0x7<<ADC_MIC1G),
		(mainmic_val<<ADC_MIC1G));
	snd_soc_update_bits(codec, ADC_SRCBST_CTRL, (0x7<<ADC_MIC2G),
		(headsetmic_val<<ADC_MIC2G));
	if (dmic_used)
		snd_soc_write(codec, ADC_VOL_CTRL, adc_digital_val);
#if 0
	if (agc_used)
		agc_config(codec);
#endif
	if (drc_used)
		drc_config(codec);

	/*headphone calibration clock frequency select*/
	snd_soc_update_bits(codec, SPKOUT_CTRL, (0x7<<HPCALICKS),
		(0x7<<HPCALICKS));

}

static int late_enable_dac(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->dac_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		AC100_DBG("%s,line:%d\n", __func__, __LINE__);
		if (ac100->dac_enable == 0) {
			/*enable dac module clk*/
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_DAC_DIG),
				(0x1<<MOD_CLK_DAC_DIG));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_DAC_DIG),
				(0x1<<MOD_RESET_DAC_DIG));
			snd_soc_update_bits(codec, DAC_DIG_CTRL,
				(0x1<<ENDA), (0x1<<ENDA));
		}
		ac100->dac_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->dac_enable > 0) {
			ac100->dac_enable--;
			if (ac100->dac_enable == 0) {
				snd_soc_update_bits(codec, DAC_DIG_CTRL,
					(0x1<<ENDA), (0x0<<ENDA));
				/*disable dac module clk*/
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_DAC_DIG),
					(0x0<<MOD_CLK_DAC_DIG));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_DAC_DIG),
					(0x0<<MOD_RESET_DAC_DIG));
			}
		}
		break;
	}
	mutex_unlock(&ac100->dac_mutex);
	return 0;
}

static int late_enable_adc(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->adc_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (ac100->adc_enable == 0) {
			/*enable adc module clk*/
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_ADC_DIG),
				(0x1<<MOD_CLK_ADC_DIG));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_ADC_DIG),
				(0x1<<MOD_RESET_ADC_DIG));
			/* fix noise, but cannot record sound:fix me */
			/*snd_soc_update_bits(codec, ADC_DIG_CTRL,*/
			/*	(0x3<<ADOUT_DTS), (0x2<<ADOUT_DTS));*/
			/*snd_soc_update_bits(codec, ADC_DIG_CTRL,*/
			/*	(0x1<<ADOUT_DLY), (0x1<<ADOUT_DLY));*/
			snd_soc_update_bits(codec, ADC_DIG_CTRL,
				(0x1<<ENAD), (0x1<<ENAD));
		}
		ac100->adc_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->adc_enable > 0) {
			ac100->adc_enable--;
			if (ac100->adc_enable == 0) {
				snd_soc_update_bits(codec, ADC_DIG_CTRL,
					(0x1<<ENAD), (0x0<<ENAD));
				/*disable adc module clk*/
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_ADC_DIG),
					(0x0<<MOD_CLK_ADC_DIG));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_ADC_DIG),
					(0x0<<MOD_RESET_ADC_DIG));
			}
		}
		break;
	}
	mutex_unlock(&ac100->adc_mutex);
	return 0;
}

static int ac100_speaker_event(struct snd_soc_dapm_widget *w,
				struct snd_kcontrol *k,
				int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		AC100_DBG("[speaker open ]%s,line:%d\n", __func__, __LINE__);
		if (drc_used)
			drc_enable(codec, 1);

		msleep(30);
		if (spkgpio.used)
			gpio_set_value(spkgpio.gpio, 1);
		break;
	case SND_SOC_DAPM_PRE_PMD:
		AC100_DBG("[speaker close ]%s,line:%d\n", __func__, __LINE__);
		if (spkgpio.used)
			gpio_set_value(spkgpio.gpio, 0);
		if (drc_used)
			drc_enable(codec, 0);
		break;
	default:
		break;

	}
	return 0;
}

static int ac100_earpiece_event(struct snd_soc_dapm_widget *w,
				struct snd_kcontrol *k,
				int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		AC100_DBG("[earpiece open ]%s,line:%d\n", __func__, __LINE__);
		snd_soc_update_bits(codec, ESPKOUT_CTRL,
			(0x1<<ESPPA_EN), (0x1<<ESPPA_EN));
		break;
	case SND_SOC_DAPM_PRE_PMD:
		AC100_DBG("[earpiece close ]%s,line:%d\n", __func__, __LINE__);
		snd_soc_update_bits(codec, ESPKOUT_CTRL,
			(0x1<<ESPPA_EN), (0x0<<ESPPA_EN));
	default:
		break;

	}
	return 0;
}

static int ac100_headphone_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k,	int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		/*open*/
		AC100_DBG("post:open:%s,line:%d\n", __func__, __LINE__);
		snd_soc_update_bits(codec, OMIXER_DACA_CTRL,
			(0xf<<HPOUTPUTENABLE), (0xf<<HPOUTPUTENABLE));
		snd_soc_update_bits(codec, HPOUT_CTRL,
			(0x1<<HPPA_EN), (0x1<<HPPA_EN));
		msleep(20);
		snd_soc_update_bits(codec, HPOUT_CTRL,
			(0x3<<LHPPA_MUTE), (0x3<<LHPPA_MUTE));
		break;
	case SND_SOC_DAPM_PRE_PMD:
		/*close*/
		AC100_DBG("pre:close:%s,line:%d\n", __func__, __LINE__);
		snd_soc_update_bits(codec, HPOUT_CTRL,
			(0x1<<HPPA_EN), (0x0<<HPPA_EN));
		snd_soc_update_bits(codec, OMIXER_DACA_CTRL,
			(0xf<<HPOUTPUTENABLE), (0x0<<HPOUTPUTENABLE));
		snd_soc_update_bits(codec, HPOUT_CTRL,
			(0x3<<LHPPA_MUTE), (0x0<<LHPPA_MUTE));
		break;
	}
	return 0;
}

int ac100_aif1clk(struct snd_soc_dapm_widget *w,
		  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (ac100->aif1_clken == 0) {
			/*enable AIF1CLK*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x1<<AIF1CLK_ENA), (0x1<<AIF1CLK_ENA));
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_AIF1), (0x1<<MOD_CLK_AIF1));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_AIF1), (0x1<<MOD_RESET_AIF1));

			/*enable systemclk*/
			if (ac100->aif2_clken == 0 && ac100->aif3_clken == 0)
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<SYSCLK_ENA), (0x1<<SYSCLK_ENA));
		}
		ac100->aif1_clken++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->aif1_clken > 0) {
			ac100->aif1_clken--;
			if (ac100->aif1_clken == 0) {
				/*disable AIF1CLK*/
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<AIF1CLK_ENA),
					(0x0<<AIF1CLK_ENA));
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_AIF1),
					(0x0<<MOD_CLK_AIF1));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_AIF1),
					(0x0<<MOD_RESET_AIF1));
				/*DISABLE systemclk*/
				if (ac100->aif2_clken == 0 &&
					ac100->aif3_clken == 0)
					snd_soc_update_bits(codec, SYSCLK_CTRL,
						(0x1<<SYSCLK_ENA),
						(0x0<<SYSCLK_ENA));
			}
		}
		break;
	}
	mutex_unlock(&ac100->aifclk_mutex);
	return 0;
}

int ac100_aif2clk(struct snd_soc_dapm_widget *w,
		  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (ac100->aif2_clken == 0) {
			/*enable AIF2CLK*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x1<<AIF2CLK_ENA), (0x1<<AIF2CLK_ENA));
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_AIF2), (0x1<<MOD_CLK_AIF2));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_AIF2), (0x1<<MOD_RESET_AIF2));
			/*enable systemclk*/
			if (ac100->aif1_clken == 0 && ac100->aif3_clken == 0)
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<SYSCLK_ENA), (0x1<<SYSCLK_ENA));
		}
		ac100->aif2_clken++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->aif2_clken > 0) {
			ac100->aif2_clken--;
			if (ac100->aif2_clken == 0) {
				/*disable AIF2CLK*/
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<AIF2CLK_ENA),
					(0x0<<AIF2CLK_ENA));
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_AIF2),
					(0x0<<MOD_CLK_AIF2));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_AIF2),
					(0x0<<MOD_RESET_AIF2));
				/*DISABLE systemclk*/
				if (ac100->aif1_clken == 0 &&
					ac100->aif3_clken == 0)
					snd_soc_update_bits(codec, SYSCLK_CTRL,
						(0x1<<SYSCLK_ENA),
						(0x0<<SYSCLK_ENA));
			}
		}
		break;
	}
	mutex_unlock(&ac100->aifclk_mutex);
	return 0;
}

int ac100_aif3clk(struct snd_soc_dapm_widget *w,
		  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (ac100->aif2_clken == 0) {
			/*enable AIF2CLK*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x1<<AIF2CLK_ENA), (0x1<<AIF2CLK_ENA));
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_AIF2), (0x1<<MOD_CLK_AIF2));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_AIF2), (0x1<<MOD_RESET_AIF2));
			/*enable systemclk*/
			if (ac100->aif1_clken == 0 && ac100->aif3_clken == 0)
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<SYSCLK_ENA), (0x1<<SYSCLK_ENA));
		}
		ac100->aif2_clken++;
		if (ac100->aif3_clken == 0) {
			/*enable AIF3CLK*/
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_AIF3), (0x1<<MOD_CLK_AIF3));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_AIF3), (0x1<<MOD_RESET_AIF3));
		}
		ac100->aif3_clken++;

		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->aif2_clken > 0) {
			ac100->aif2_clken--;
			if (ac100->aif2_clken == 0) {
				/*disable AIF2CLK*/
				snd_soc_update_bits(codec, SYSCLK_CTRL,
					(0x1<<AIF2CLK_ENA),
					(0x0<<AIF2CLK_ENA));
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_AIF2),
					(0x0<<MOD_CLK_AIF2));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_AIF2),
					(0x0<<MOD_RESET_AIF2));
				/*DISABLE systemclk*/
				if (ac100->aif1_clken == 0 &&
					ac100->aif3_clken == 0)
					snd_soc_update_bits(codec, SYSCLK_CTRL,
						(0x1<<SYSCLK_ENA),
						(0x0<<SYSCLK_ENA));
			}
		}
		if (ac100->aif3_clken > 0) {
			ac100->aif3_clken--;
			if (ac100->aif3_clken == 0) {
				/*enable AIF3CLK*/
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_AIF3),
					(0x0<<MOD_CLK_AIF3));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_AIF3),
					(0x0<<MOD_RESET_AIF3));
			}
		}

		break;
	}
	mutex_unlock(&ac100->aifclk_mutex);
	return 0;
}

static int aif2inl_vir_event(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_update_bits(codec, AIF3_SGP_CTRL,
			(0x3<<AIF2_DAC_SRC), (0x1<<AIF2_DAC_SRC));
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_update_bits(codec, AIF3_SGP_CTRL,
			(0x3<<AIF2_DAC_SRC), (0x0<<AIF2_DAC_SRC));
		break;
	}
	return 0;
}

static int aif2inr_vir_event(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_update_bits(codec, AIF3_SGP_CTRL,
			(0x3<<AIF2_DAC_SRC), (0x2<<AIF2_DAC_SRC));
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_update_bits(codec, AIF3_SGP_CTRL,
			(0x3<<AIF2_DAC_SRC), (0x0<<AIF2_DAC_SRC));
		break;
	}
	return 0;
}

static int dmic_mux_ev(struct snd_soc_dapm_widget *w,
		      struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_update_bits(codec, ADC_DIG_CTRL,
			(0x1<<ENDM), (0x1<<ENDM));
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_update_bits(codec, ADC_DIG_CTRL,
			(0x1<<ENDM), (0x0<<ENDM));
		break;
	}
	mutex_lock(&ac100->adc_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (ac100->adc_enable == 0) {
			/*enable adc module clk*/
			snd_soc_update_bits(codec, MOD_CLK_ENA,
				(0x1<<MOD_CLK_ADC_DIG),
				(0x1<<MOD_CLK_ADC_DIG));
			snd_soc_update_bits(codec, MOD_RST_CTRL,
				(0x1<<MOD_RESET_ADC_DIG),
				(0x1<<MOD_RESET_ADC_DIG));
			snd_soc_update_bits(codec, ADC_DIG_CTRL,
				(0x1<<ENAD), (0x1<<ENAD));
		}
		ac100->adc_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (ac100->adc_enable > 0) {
			ac100->adc_enable--;
			if (ac100->adc_enable == 0) {
				snd_soc_update_bits(codec, ADC_DIG_CTRL,
					(0x1<<ENAD), (0x0<<ENAD));
				/*disable adc module clk*/
				snd_soc_update_bits(codec, MOD_CLK_ENA,
					(0x1<<MOD_CLK_ADC_DIG),
					(0x0<<MOD_CLK_ADC_DIG));
				snd_soc_update_bits(codec, MOD_RST_CTRL,
					(0x1<<MOD_RESET_ADC_DIG),
					(0x0<<MOD_RESET_ADC_DIG));
			}
		}
		break;
	}
	mutex_unlock(&ac100->adc_mutex);
	return 0;
}

static const DECLARE_TLV_DB_SCALE(headphone_vol_tlv, -6300, 100, 0);
static const DECLARE_TLV_DB_SCALE(lineout_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(speaker_vol_tlv, -4800, 150, 0);
static const DECLARE_TLV_DB_SCALE(earpiece_vol_tlv, -4350, 150, 0);

static const DECLARE_TLV_DB_SCALE(aif1_ad_slot0_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot1_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_da_slot0_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_da_slot1_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot0_mix_vol_tlv, -600, 600, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot1_mix_vol_tlv, -600, 600, 0);

static const DECLARE_TLV_DB_SCALE(aif2_ad_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif2_da_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif2_ad_mix_vol_tlv, -600, 600, 0);

static const DECLARE_TLV_DB_SCALE(adc_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(dac_vol_tlv, -11925, 75, 0);

static const DECLARE_TLV_DB_SCALE(dig_vol_tlv, -7308, 116, 0);
static const DECLARE_TLV_DB_SCALE(dac_mix_vol_tlv, -600, 600, 0);
static const DECLARE_TLV_DB_SCALE(adc_input_vol_tlv, -450, 150, 0);

/*mic1/mic2: 0db when 000, and from 30db to 48db when 001 to 111*/
static const DECLARE_TLV_DB_SCALE(mic1_boost_vol_tlv, 0, 200, 0);
static const DECLARE_TLV_DB_SCALE(mic2_boost_vol_tlv, 0, 200, 0);

static const DECLARE_TLV_DB_SCALE(linein_amp_vol_tlv, -1200, 300, 0);
static const DECLARE_TLV_DB_SCALE(axui_amp_vol_tlv, -1200, 300, 0);

static const DECLARE_TLV_DB_SCALE(axin_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic1_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic2_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(linein_to_l_r_mix_vol_tlv, -450, 150, 0);

static const struct snd_kcontrol_new ac100_controls[] = {
	/*AIF1*/
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 0 volume", AIF1_VOL_CTRL1,
		AIF1_AD0L_VOL, AIF1_AD0R_VOL, 0xff, 0, aif1_ad_slot0_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 1 volume", AIF1_VOL_CTRL2,
		AIF1_AD1L_VOL, AIF1_AD1R_VOL, 0xff, 0, aif1_ad_slot1_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 DAC timeslot 0 volume", AIF1_VOL_CTRL3,
		AIF1_DA0L_VOL, AIF1_DA0R_VOL, 0xff, 0, aif1_da_slot0_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 DAC timeslot 1 volume", AIF1_VOL_CTRL4,
		AIF1_DA1L_VOL, AIF1_DA1R_VOL, 0xff, 0, aif1_da_slot1_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 0 mixer gain", AIF1_MXR_GAIN,
		AIF1_AD0L_MXR_GAIN, AIF1_AD0R_MXR_GAIN,
		0xf, 0, aif1_ad_slot0_mix_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 1 mixer gain", AIF1_MXR_GAIN,
		AIF1_AD1L_MXR_GAIN, AIF1_AD1R_MXR_GAIN,
		0x3, 0, aif1_ad_slot1_mix_vol_tlv),

	/*AIF2*/
	SOC_DOUBLE_TLV("AIF2 ADC volume", AIF2_VOL_CTRL1, AIF2_ADCL_VOL,
		AIF2_ADCR_VOL, 0xff, 0, aif2_ad_vol_tlv),
	SOC_DOUBLE_TLV("AIF2 DAC volume", AIF2_VOL_CTRL2, AIF2_DACL_VOL,
		AIF2_DACR_VOL, 0xff, 0, aif2_da_vol_tlv),
	SOC_DOUBLE_TLV("AIF2 ADC mixer gain", AIF2_MXR_GAIN,
		AIF2_ADCL_MXR_GAIN, AIF2_ADCR_MXR_GAIN,
		0xf, 0, aif2_ad_mix_vol_tlv),

	/*ADC*/
	SOC_DOUBLE_TLV("ADC volume", ADC_VOL_CTRL, ADC_VOL_L, ADC_VOL_R,
		0xff, 0, adc_vol_tlv),
	/*DAC*/
	SOC_DOUBLE_TLV("DAC volume", DAC_VOL_CTRL, DAC_VOL_L, DAC_VOL_R,
		0xff, 0, dac_vol_tlv),
	SOC_DOUBLE_TLV("DAC mixer gain", DAC_MXR_GAIN, DACL_MXR_GAIN,
		DACR_MXR_GAIN, 0xf, 0, dac_mix_vol_tlv),

	SOC_SINGLE_TLV("digital volume", DAC_DBG_CTRL, DVC,
		0x3f, 0, dig_vol_tlv),

	/*ADC*/
	SOC_SINGLE_TLV("LADC input gain", ADC_APC_CTRL, ADCLG,
		0x7, 0, adc_input_vol_tlv),
	SOC_SINGLE_TLV("RADC input gain", ADC_APC_CTRL, ADCRG,
		0x7, 0, adc_input_vol_tlv),

	SOC_SINGLE_TLV("MIC1 boost amplifier gain", ADC_SRCBST_CTRL, ADC_MIC1G,
		0x7, 0, mic1_boost_vol_tlv),
	SOC_SINGLE_TLV("MIC2 boost amplifier gain", ADC_SRCBST_CTRL, ADC_MIC2G,
		0x7, 0, mic2_boost_vol_tlv),
	SOC_SINGLE_TLV("LINEINL-LINEINR pre-amplifier gain", ADC_SRCBST_CTRL,
		LINEIN_PREG, 0x7, 0, linein_amp_vol_tlv),
	SOC_SINGLE_TLV("AUXI pre-amplifier gain", ADC_SRCBST_CTRL, AUXI_PREG,
		0x7, 0, axui_amp_vol_tlv),

	SOC_SINGLE_TLV("AXin to L_R output mixer gain", OMIXER_BST1_CTRL, AXG,
		0x7, 0, axin_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("MIC1 BST stage to L_R outp mixer gain",
		OMIXER_BST1_CTRL, OMIXER_MIC1G,
		0x7, 0, mic1_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("MIC2 BST stage to L_R outp mixer gain",
		OMIXER_BST1_CTRL, OMIXER_MIC2G,
		0x7, 0, mic2_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("LINEINL/R to L_R output mixer gain",
		OMIXER_BST1_CTRL, LINEING, 0x7, 0, linein_to_l_r_mix_vol_tlv),

	SOC_SINGLE_TLV("earpiece volume", ESPKOUT_CTRL, ESP_VOL,
		0x1f, 0, earpiece_vol_tlv),
	SOC_SINGLE_TLV("speaker volume", SPKOUT_CTRL, SPK_VOL,
		0x1f, 0, speaker_vol_tlv),
	SOC_SINGLE_TLV("line out volume", LOUT_CTRL, LINEOUTG,
		0x7, 0, lineout_vol_tlv),
	SOC_SINGLE_TLV("headphone volume", HPOUT_CTRL, HP_VOL,
		0x3f, 0, headphone_vol_tlv),
};
/*AIF1 AD0 OUT */
static const char * const aif1out0l_text[] = {
	"AIF1_AD0L", "AIF1_AD0R",
	"SUM_AIF1AD0L_AIF1AD0R", "AVE_AIF1AD0L_AIF1AD0R"
};
static const char * const aif1out0r_text[] = {
	"AIF1_AD0R", "AIF1_AD0L",
	"SUM_AIF1AD0L_AIF1AD0R", "AVE_AIF1AD0L_AIF1AD0R"
};

static const struct soc_enum aif1out0l_enum =
	SOC_ENUM_SINGLE(AIF1_ADCDAT_CTRL, AIF1_AD0L_SRC,
		ARRAY_SIZE(aif1out0l_text), aif1out0l_text);

static const struct snd_kcontrol_new aif1out0l_mux =
	SOC_DAPM_ENUM("AIF1OUT0L Mux", aif1out0l_enum);

static const struct soc_enum aif1out0r_enum =
	SOC_ENUM_SINGLE(AIF1_ADCDAT_CTRL, AIF1_AD0R_SRC,
		ARRAY_SIZE(aif1out0r_text), aif1out0r_text);

static const struct snd_kcontrol_new aif1out0r_mux =
	SOC_DAPM_ENUM("AIF1OUT0R Mux", aif1out0r_enum);

/*AIF1 AD1 OUT */
static const char * const aif1out1l_text[] = {
	"AIF1_AD1L", "AIF1_AD1R",
	"SUM_AIF1ADC1L_AIF1ADC1R", "AVE_AIF1ADC1L_AIF1ADC1R"
};
static const char * const aif1out1r_text[] = {
	"AIF1_AD1R", "AIF1_AD1L",
	"SUM_AIF1ADC1L_AIF1ADC1R", "AVE_AIF1ADC1L_AIF1ADC1R"
};

static const struct soc_enum aif1out1l_enum =
	SOC_ENUM_SINGLE(AIF1_ADCDAT_CTRL, AIF1_AD1L_SRC,
		ARRAY_SIZE(aif1out1l_text), aif1out1l_text);

static const struct snd_kcontrol_new aif1out1l_mux =
	SOC_DAPM_ENUM("AIF1OUT1L Mux", aif1out1l_enum);

static const struct soc_enum aif1out1r_enum =
	SOC_ENUM_SINGLE(AIF1_ADCDAT_CTRL, AIF1_AD1R_SRC,
		ARRAY_SIZE(aif1out1r_text), aif1out1r_text);

static const struct snd_kcontrol_new aif1out1r_mux =
	SOC_DAPM_ENUM("AIF1OUT1R Mux", aif1out1r_enum);

/*AIF1 DA0 IN*/
static const char * const aif1in0l_text[] = {
	"AIF1_DA0L", "AIF1_DA0R",
	"SUM_AIF1DA0L_AIF1DA0R", "AVE_AIF1DA0L_AIF1DA0R"
};
static const char * const aif1in0r_text[] = {
	"AIF1_DA0R", "AIF1_DA0L",
	"SUM_AIF1DA0L_AIF1DA0R", "AVE_AIF1DA0L_AIF1DA0R"
};

static const struct soc_enum aif1in0l_enum =
	SOC_ENUM_SINGLE(AIF1_DACDAT_CTRL, AIF1_DA0L_SRC,
		ARRAY_SIZE(aif1in0l_text), aif1in0l_text);

static const struct snd_kcontrol_new aif1in0l_mux =
	SOC_DAPM_ENUM("AIF1IN0L Mux", aif1in0l_enum);

static const struct soc_enum aif1in0r_enum =
	SOC_ENUM_SINGLE(AIF1_DACDAT_CTRL, AIF1_DA0R_SRC,
		ARRAY_SIZE(aif1in0r_text), aif1in0r_text);

static const struct snd_kcontrol_new aif1in0r_mux =
	SOC_DAPM_ENUM("AIF1IN0R Mux", aif1in0r_enum);

/*AIF1 DA1 IN*/
static const char * const aif1in1l_text[] = {
	"AIF1_DA1L", "AIF1_DA1R",
	"SUM_AIF1DA1L_AIF1DA1R", "AVE_AIF1DA1L_AIF1DA1R"
};
static const char * const aif1in1r_text[] = {
	"AIF1_DA1R", "AIF1_DA1L",
	"SUM_AIF1DA1L_AIF1DA1R", "AVE_AIF1DA1L_AIF1DA1R"
};

static const struct soc_enum aif1in1l_enum =
	SOC_ENUM_SINGLE(AIF1_DACDAT_CTRL, AIF1_DA1L_SRC,
		ARRAY_SIZE(aif1in1l_text), aif1in1l_text);

static const struct snd_kcontrol_new aif1in1l_mux =
	SOC_DAPM_ENUM("AIF1IN1L Mux", aif1in1l_enum);

static const struct soc_enum aif1in1r_enum =
	SOC_ENUM_SINGLE(AIF1_DACDAT_CTRL, AIF1_DA1R_SRC,
		ARRAY_SIZE(aif1in1r_text), aif1in1r_text);

static const struct snd_kcontrol_new aif1in1r_mux =
	SOC_DAPM_ENUM("AIF1IN1R Mux", aif1in1r_enum);

/*0x13register*/
/*AIF1 ADC0 MIXER SOURCE*/
static const struct snd_kcontrol_new aif1_ad0l_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF1 DA0L Switch",
		AIF1_MXR_SRC, AIF1_AD0L_AIF1_DA0L_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch",
		AIF1_MXR_SRC, AIF1_AD0L_AIF2_DACL_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch",
		AIF1_MXR_SRC, AIF1_AD0L_ADCL_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch",
		AIF1_MXR_SRC, AIF1_AD0L_AIF2_DACR_MXR, 1, 0),
};
static const struct snd_kcontrol_new aif1_ad0r_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF1 DA0R Switch",
		AIF1_MXR_SRC, AIF1_AD0R_AIF1_DA0R_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch",
		AIF1_MXR_SRC, AIF1_AD0R_AIF2_DACR_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch", AIF1_MXR_SRC, AIF1_AD0R_ADCR_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch",
		AIF1_MXR_SRC, AIF1_AD0R_AIF2_DACL_MXR, 1, 0),
};

/*AIF1 ADC1 MIXER SOURCE*/
static const struct snd_kcontrol_new aif1_ad1l_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF2 DACL Switch",
		AIF1_MXR_SRC, AIF1_AD1L_AIF2_DACL_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch", AIF1_MXR_SRC, AIF1_AD1L_ADCL_MXR, 1, 0),
};
static const struct snd_kcontrol_new aif1_ad1r_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF2 DACR Switch",
		AIF1_MXR_SRC, AIF1_AD1R_AIF2_DACR_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch",
		AIF1_MXR_SRC, AIF1_AD1R_ADCR_MXR, 1, 0),
};

/*4C register*/
static const struct snd_kcontrol_new dacl_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("ADCL Switch", DAC_MXR_SRC, DACL_MXR_ADCL, 1, 0),
	SOC_DAPM_SINGLE("AIF2DACL Switch",
		DAC_MXR_SRC, DACL_MXR_AIF2_DACL, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA1L Switch",
		DAC_MXR_SRC, DACL_MXR_AIF1_DA1L, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA0L Switch",
		DAC_MXR_SRC, DACL_MXR_AIF1_DA0L, 1, 0),
};
static const struct snd_kcontrol_new dacr_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("ADCR Switch", DAC_MXR_SRC, DACR_MXR_ADCR, 1, 0),
	SOC_DAPM_SINGLE("AIF2DACR Switch",
		DAC_MXR_SRC, DACR_MXR_AIF2_DACR, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA1R Switch",
		DAC_MXR_SRC, DACR_MXR_AIF1_DA1R, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA0R Switch",
		DAC_MXR_SRC, DACR_MXR_AIF1_DA0R, 1, 0),
};

/*output mixer source select*/
/*defined left output mixer*/
static const struct snd_kcontrol_new ac100_loutmix_controls[] = {
	SOC_DAPM_SINGLE("DACR Switch", OMIXER_SR, LMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("DACL Switch", OMIXER_SR, LMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("AUXINL Switch", OMIXER_SR, LMIXMUTEAUXINL, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch", OMIXER_SR, LMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("LINEINL-LINEINR Switch",
		OMIXER_SR, LMIXMUTELINEINLR, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch",
		OMIXER_SR, LMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch",
		OMIXER_SR, LMIXMUTEMIC1BOOST, 1, 0),
};

/*defined right output mixer*/
static const struct snd_kcontrol_new ac100_routmix_controls[] = {
	SOC_DAPM_SINGLE("DACL Switch", OMIXER_SR, RMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("DACR Switch", OMIXER_SR, RMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("AUXINR Switch", OMIXER_SR, RMIXMUTEAUXINR, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch", OMIXER_SR, RMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("LINEINL-LINEINR Switch",
		OMIXER_SR, RMIXMUTELINEINLR, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch",
		OMIXER_SR, RMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch",
		OMIXER_SR, RMIXMUTEMIC1BOOST, 1, 0),
};

/*hp source select*/
/*headphone input source*/
static const char * const ac100_hp_r_func_sel[] = {
	"DACR HPR Switch", "Right Analog Mixer HPR Switch"};
static const struct soc_enum ac100_hp_r_func_enum =
	SOC_ENUM_SINGLE(HPOUT_CTRL, RHPS, 2, ac100_hp_r_func_sel);

static const struct snd_kcontrol_new ac100_hp_r_func_controls =
	SOC_DAPM_ENUM("HP_R Mux", ac100_hp_r_func_enum);

static const char * const ac100_hp_l_func_sel[] = {
	"DACL HPL Switch", "Left Analog Mixer HPL Switch"};
static const struct soc_enum ac100_hp_l_func_enum =
	SOC_ENUM_SINGLE(HPOUT_CTRL, LHPS, 2, ac100_hp_l_func_sel);

static const struct snd_kcontrol_new ac100_hp_l_func_controls =
	SOC_DAPM_ENUM("HP_L Mux", ac100_hp_l_func_enum);

/*spk source select*/
static const char * const ac100_rspks_func_sel[] = {
	"MIXER Switch", "MIXR MIXL Switch"};
static const struct soc_enum ac100_rspks_func_enum =
	SOC_ENUM_SINGLE(SPKOUT_CTRL, RSPKS, 2, ac100_rspks_func_sel);

static const struct snd_kcontrol_new ac100_rspks_func_controls =
	SOC_DAPM_ENUM("SPK_R Mux", ac100_rspks_func_enum);

static const char * const ac100_lspks_l_func_sel[] = {
	"MIXEL Switch", "MIXL MIXR  Switch"};
static const struct soc_enum ac100_lspks_func_enum =
	SOC_ENUM_SINGLE(SPKOUT_CTRL, LSPKS, 2, ac100_lspks_l_func_sel);

static const struct snd_kcontrol_new ac100_lspks_func_controls =
	SOC_DAPM_ENUM("SPK_L Mux", ac100_lspks_func_enum);

/*earpiece source select*/
static const char * const ac100_earpiece_func_sel[] = {
	"DACR", "DACL", "Right Analog Mixer", "Left Analog Mixer"};
static const struct soc_enum ac100_earpiece_func_enum =
	SOC_ENUM_SINGLE(ESPKOUT_CTRL, ESPSR, 4, ac100_earpiece_func_sel);

static const struct snd_kcontrol_new ac100_earpiece_func_controls =
	SOC_DAPM_ENUM("EAR Mux", ac100_earpiece_func_enum);

/*AIF2 out */
static const char * const aif2outl_text[] = {
	"AIF2_ADCL", "AIF2_ADCR",
	"SUM_AIF2_ADCL_AIF2_ADCR", "AVE_AIF2_ADCL_AIF2_ADCR"
};
static const char * const aif2outr_text[] = {
	"AIF2_ADCR", "AIF2_ADCL",
	"SUM_AIF2_ADCL_AIF2_ADCR", "AVE_AIF2_ADCL_AIF2_ADCR"
};

static const struct soc_enum aif2outl_enum =
	SOC_ENUM_SINGLE(AIF2_ADCDAT_CTRL, AIF2_ADCL_SRC,
		ARRAY_SIZE(aif2outl_text), aif2outl_text);

static const struct snd_kcontrol_new aif2outl_mux =
	SOC_DAPM_ENUM("AIF2OUTL Mux", aif2outl_enum);

static const struct soc_enum aif2outr_enum =
	SOC_ENUM_SINGLE(AIF2_ADCDAT_CTRL, AIF2_ADCR_SRC,
		ARRAY_SIZE(aif2outr_text), aif2outr_text);

static const struct snd_kcontrol_new aif2outr_mux =
	SOC_DAPM_ENUM("AIF2OUTR Mux", aif2outr_enum);

/*AIF2 IN*/
static const char * const aif2inl_text[] = {
	"AIF2_DACL", "AIF2_DACR",
	"SUM_AIF2DACL_AIF2DACR", "AVE_AIF2DACL_AIF2DACR"
};
static const char * const aif2inr_text[] = {
	"AIF2_DACR", "AIF2_DACL",
	"SUM_AIF2DACL_AIF2DACR", "AVE_AIF2DACL_AIF2DACR"
};

static const struct soc_enum aif2inl_enum =
	SOC_ENUM_SINGLE(AIF2_DACDAT_CTRL, AIF2_DACL_SRC,
		ARRAY_SIZE(aif2inl_text), aif2inl_text);

static const struct snd_kcontrol_new aif2inl_mux =
	SOC_DAPM_ENUM("AIF2INL Mux", aif2inl_enum);

static const struct soc_enum aif2inr_enum =
	SOC_ENUM_SINGLE(AIF2_DACDAT_CTRL, AIF2_DACR_SRC,
		ARRAY_SIZE(aif2inr_text), aif2inr_text);

static const struct snd_kcontrol_new aif2inr_mux =
	SOC_DAPM_ENUM("AIF2INR Mux", aif2inr_enum);

/*23 REGIDTER*/
/*AIF2 source select*/
static const struct snd_kcontrol_new aif2_adcl_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("AIF1 DA0L Switch", AIF2_MXR_SRC,
		AIF2_ADCL_AIF1DA0L_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF1 DA1L Switch", AIF2_MXR_SRC,
		AIF2_ADCL_AIF1DA1L_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch", AIF2_MXR_SRC,
		AIF2_ADCL_AIF2DACR_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch", AIF2_MXR_SRC, AIF2_ADCL_ADCL_MXR, 1, 0),
};
static const struct snd_kcontrol_new aif2_adcr_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("AIF1 DA0R Switch", AIF2_MXR_SRC,
		AIF2_ADCR_AIF1DA0R_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF1 DA1R Switch", AIF2_MXR_SRC,
		AIF2_ADCR_AIF1DA1R_MXR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch", AIF2_MXR_SRC,
		AIF2_ADCR_AIF2DACL_MXR, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch", AIF2_MXR_SRC, AIF2_ADCR_ADCR_MXR, 1, 0),
};

/*aif3 out 33 REGISTER*/
static const char * const aif3out_text[] = {
	"AIF2 ADC left channel", "AIF2 ADC right channel"
};

static const unsigned int aif3out_values[] = {1, 2};

static const struct soc_enum aif3out_enum =
	SOC_VALUE_ENUM_SINGLE(AIF3_SGP_CTRL, AIF3_ADC_SRC, 3,
		ARRAY_SIZE(aif3out_text), aif3out_text, aif3out_values);

static const struct snd_kcontrol_new aif3out_mux =
	SOC_DAPM_ENUM("AIF3OUT Mux", aif3out_enum);

/*aif2 DAC INPUT SOURCE SELECT 33 REGISTER*/
static const char * const aif2dacin_text[] = {
	"Left_s right_s AIF2", "Left_s AIF3 Right_s AIF2",
	"Left_s AIF2 Right_s AIF3"
};

static const struct soc_enum aif2dacin_enum =
	SOC_ENUM_SINGLE(AIF3_SGP_CTRL, AIF2_DAC_SRC, 3, aif2dacin_text);

static const struct snd_kcontrol_new aif2dacin_mux =
	SOC_DAPM_ENUM("AIF2 DAC SRC Mux", aif2dacin_enum);

/*ADC SOURCE SELECT*/
/*defined left input adc mixer*/
static const struct snd_kcontrol_new ac100_ladcmix_controls[] = {
	SOC_DAPM_SINGLE("MIC1 boost Switch",
		ADC_SRC, LADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch",
		ADC_SRC, LADCMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("LININL-R Switch",
		ADC_SRC, LADCMIXMUTELINEINLR, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch",
		ADC_SRC, LADCMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("AUXINL Switch",
		ADC_SRC, LADCMIXMUTEAUXINL, 1, 0),
	SOC_DAPM_SINGLE("Lout_Mixer_Switch",
		ADC_SRC, LADCMIXMUTELOUTPUT, 1, 0),
	SOC_DAPM_SINGLE("Rout_Mixer_Switch",
		ADC_SRC, LADCMIXMUTEROUTPUT, 1, 0),
};

/*defined right input adc mixer*/
static const struct snd_kcontrol_new ac100_radcmix_controls[] = {
	SOC_DAPM_SINGLE("MIC1 boost Switch",
		ADC_SRC, RADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch",
		ADC_SRC, RADCMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("LINEINL-R Switch",
		ADC_SRC, RADCMIXMUTELINEINLR, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch",
		ADC_SRC, RADCMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("AUXINR Switch",
		ADC_SRC, RADCMIXMUTEAUXINR, 1, 0),
	SOC_DAPM_SINGLE("Rout_Mixer_Switch",
		ADC_SRC, RADCMIXMUTEROUTPUT, 1, 0),
	SOC_DAPM_SINGLE("Lout_Mixer_Switch",
		ADC_SRC, RADCMIXMUTELOUTPUT, 1, 0),
};

/*mic2 source select*/
static const char * const mic2src_text[] = {
	"MIC2", "MIC3"};

static const struct soc_enum mic2src_enum =
	SOC_ENUM_SINGLE(ADC_SRCBST_CTRL, MIC2SLT,
		ARRAY_SIZE(mic2src_text), mic2src_text);

static const struct snd_kcontrol_new mic2src_mux =
	SOC_DAPM_ENUM("MIC2 SRC", mic2src_enum);
/*59 register*/
/*defined lineout mixer*/
static const struct snd_kcontrol_new lineout_mix_controls[] = {
	SOC_DAPM_SINGLE("MIC1 boost Switch", LOUT_CTRL, LINEOUTS0, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch", LOUT_CTRL, LINEOUTS1, 1, 0),
	SOC_DAPM_SINGLE("Rout_Mixer_Switch", LOUT_CTRL, LINEOUTS2, 1, 0),
	SOC_DAPM_SINGLE("Lout_Mixer_Switch", LOUT_CTRL, LINEOUTS3, 1, 0),
};
/*DMIC*/
static const char * const adc_mux_text[] = {"ADC", "DMIC"};
static const struct soc_enum adc_enum =
	SOC_ENUM_SINGLE(SND_SOC_NOPM, 0,
			ARRAY_SIZE(adc_mux_text), adc_mux_text);
static const struct snd_kcontrol_new adcl_mux =
	SOC_DAPM_ENUM("ADCL Mux", adc_enum);
static const struct snd_kcontrol_new adcr_mux =
	SOC_DAPM_ENUM("ADCR Mux", adc_enum);

/*In next four kcontrols, the register is no sense*/
static const struct snd_kcontrol_new aif2inl_aif2switch =
	SOC_DAPM_SINGLE("aif2inl aif2Switch", AIF1_RXD_CTRL, 8, 1, 0);
static const struct snd_kcontrol_new aif2inr_aif2switch =
	SOC_DAPM_SINGLE("aif2inr aif2Switch", AIF1_RXD_CTRL, 9, 1, 0);

static const struct snd_kcontrol_new aif2inl_aif3switch =
	SOC_DAPM_SINGLE("aif2inl aif3Switch", AIF1_RXD_CTRL, 10, 1, 0);
static const struct snd_kcontrol_new aif2inr_aif3switch =
	SOC_DAPM_SINGLE("aif2inr aif3Switch", AIF1_RXD_CTRL, 11, 1, 0);
/*built widget*/
static const struct snd_soc_dapm_widget ac100_dapm_widgets[] = {
	/*aif2 switch*/
	SND_SOC_DAPM_SWITCH("AIF2INL Mux switch", SND_SOC_NOPM, 0, 1,
		&aif2inl_aif2switch),
	SND_SOC_DAPM_SWITCH("AIF2INR Mux switch", SND_SOC_NOPM, 0, 1,
		&aif2inr_aif2switch),

	SND_SOC_DAPM_SWITCH("AIF2INL Mux VIR switch", SND_SOC_NOPM, 0, 1,
		&aif2inl_aif3switch),
	SND_SOC_DAPM_SWITCH("AIF2INR Mux VIR switch", SND_SOC_NOPM, 0, 1,
		&aif2inr_aif3switch),

	SND_SOC_DAPM_MUX("AIF1OUT0L Mux",
		AIF1_ADCDAT_CTRL, AIF1_AD0L_ENA, 0, &aif1out0l_mux),
	SND_SOC_DAPM_MUX("AIF1OUT0R Mux",
		AIF1_ADCDAT_CTRL, AIF1_AD0R_ENA, 0, &aif1out0r_mux),

	SND_SOC_DAPM_MUX("AIF1OUT1L Mux",
		AIF1_ADCDAT_CTRL, AIF1_AD1L_ENA, 0, &aif1out1l_mux),
	SND_SOC_DAPM_MUX("AIF1OUT1R Mux",
		AIF1_ADCDAT_CTRL, AIF1_AD1R_ENA, 0, &aif1out1r_mux),

	SND_SOC_DAPM_MUX("AIF1IN0L Mux",
		AIF1_DACDAT_CTRL, AIF1_DA0L_ENA, 0, &aif1in0l_mux),
	SND_SOC_DAPM_MUX("AIF1IN0R Mux",
		AIF1_DACDAT_CTRL, AIF1_DA0R_ENA, 0, &aif1in0r_mux),

	SND_SOC_DAPM_MUX("AIF1IN1L Mux",
		AIF1_DACDAT_CTRL, AIF1_DA1L_ENA, 0, &aif1in1l_mux),
	SND_SOC_DAPM_MUX("AIF1IN1R Mux",
		AIF1_DACDAT_CTRL, AIF1_DA1R_ENA, 0, &aif1in1r_mux),

	SND_SOC_DAPM_MIXER("AIF1 AD0L Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0l_mxr_src_ctl,
		ARRAY_SIZE(aif1_ad0l_mxr_src_ctl)),
	SND_SOC_DAPM_MIXER("AIF1 AD0R Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0r_mxr_src_ctl,
		ARRAY_SIZE(aif1_ad0r_mxr_src_ctl)),

	SND_SOC_DAPM_MIXER("AIF1 AD1L Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad1l_mxr_src_ctl,
		ARRAY_SIZE(aif1_ad1l_mxr_src_ctl)),
	SND_SOC_DAPM_MIXER("AIF1 AD1R Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad1r_mxr_src_ctl,
		ARRAY_SIZE(aif1_ad1r_mxr_src_ctl)),

	SND_SOC_DAPM_MIXER_E("DACL Mixer", OMIXER_DACA_CTRL, DACALEN, 0,
		dacl_mxr_src_controls,
		ARRAY_SIZE(dacl_mxr_src_controls),
		late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("DACR Mixer", OMIXER_DACA_CTRL, DACAREN, 0,
		dacr_mxr_src_controls,
		ARRAY_SIZE(dacr_mxr_src_controls),
		late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*dac digital enble*/
	SND_SOC_DAPM_DAC("DAC En", NULL, DAC_DIG_CTRL, ENDA, 0),

	/*ADC digital enble*/
	SND_SOC_DAPM_ADC("ADC En", NULL, ADC_DIG_CTRL, ENAD, 0),

	SND_SOC_DAPM_MIXER("Left Output Mixer", OMIXER_DACA_CTRL, LMIXEN, 0,
		ac100_loutmix_controls,
		ARRAY_SIZE(ac100_loutmix_controls)),
	SND_SOC_DAPM_MIXER("Right Output Mixer", OMIXER_DACA_CTRL, RMIXEN, 0,
		ac100_routmix_controls,
		ARRAY_SIZE(ac100_routmix_controls)),

	SND_SOC_DAPM_MUX("HP_R Mux",
		SND_SOC_NOPM, 0, 0, &ac100_hp_r_func_controls),
	SND_SOC_DAPM_MUX("HP_L Mux",
		SND_SOC_NOPM, 0, 0, &ac100_hp_l_func_controls),
	SND_SOC_DAPM_MUX("SPK_R Mux",
		SPKOUT_CTRL, RSPK_EN, 0, &ac100_rspks_func_controls),
	SND_SOC_DAPM_MUX("SPK_L Mux",
		SPKOUT_CTRL, LSPK_EN, 0, &ac100_lspks_func_controls),
	SND_SOC_DAPM_PGA("SPK_LR Adder", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MUX("EAR Mux",
		ESPKOUT_CTRL, ESPPA_MUTE, 0, &ac100_earpiece_func_controls),

	/*output widget*/
	SND_SOC_DAPM_OUTPUT("HPOUTL"),
	SND_SOC_DAPM_OUTPUT("HPOUTR"),
	SND_SOC_DAPM_OUTPUT("EAROUTP"),
	SND_SOC_DAPM_OUTPUT("EAROUTN"),
	SND_SOC_DAPM_OUTPUT("SPK1P"),
	SND_SOC_DAPM_OUTPUT("SPK2P"),
	SND_SOC_DAPM_OUTPUT("SPK1N"),
	SND_SOC_DAPM_OUTPUT("SPK2N"),

	SND_SOC_DAPM_OUTPUT("LINEOUTP"),
	SND_SOC_DAPM_OUTPUT("LINEOUTN"),

	SND_SOC_DAPM_MUX("AIF2OUTL Mux",
		AIF2_ADCDAT_CTRL, AIF2_ADCL_EN, 0, &aif2outl_mux),
	SND_SOC_DAPM_MUX("AIF2OUTR Mux",
		AIF2_ADCDAT_CTRL, AIF2_ADCR_EN, 0, &aif2outr_mux),

	SND_SOC_DAPM_MUX("AIF2INL Mux", AIF2_DACDAT_CTRL,
		AIF2_DACL_ENA, 0, &aif2inl_mux),
	SND_SOC_DAPM_MUX("AIF2INR Mux", AIF2_DACDAT_CTRL,
		AIF2_DACR_ENA, 0, &aif2inr_mux),

	SND_SOC_DAPM_PGA("AIF2INL_VIR", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_PGA("AIF2INR_VIR", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MIXER("AIF2 ADL Mixer", SND_SOC_NOPM, 0, 0,
		aif2_adcl_mxr_src_controls,
		ARRAY_SIZE(aif2_adcl_mxr_src_controls)),
	SND_SOC_DAPM_MIXER("AIF2 ADR Mixer", SND_SOC_NOPM, 0, 0,
		aif2_adcr_mxr_src_controls,
		ARRAY_SIZE(aif2_adcr_mxr_src_controls)),

	SND_SOC_DAPM_MUX("AIF3OUT Mux", SND_SOC_NOPM, 0, 0, &aif3out_mux),

/*	SND_SOC_DAPM_MUX("AIF2 DAC SRC Mux",*/
/*		SND_SOC_NOPM, 0, 0, &aif2dacin_mux),*/
	/*virtual widget*/
	SND_SOC_DAPM_PGA_E("AIF2INL Mux VIR", SND_SOC_NOPM, 0, 0, NULL, 0,
			aif2inl_vir_event,
			SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_PGA_E("AIF2INR Mux VIR", SND_SOC_NOPM, 0, 0, NULL, 0,
			aif2inr_vir_event,
			SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_MIXER_E("LEFT ADC input Mixer", ADC_APC_CTRL, ADCLEN, 0,
		ac100_ladcmix_controls,
		ARRAY_SIZE(ac100_ladcmix_controls),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("RIGHT ADC input Mixer", ADC_APC_CTRL, ADCREN, 0,
		ac100_radcmix_controls,
		ARRAY_SIZE(ac100_radcmix_controls),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	/*mic reference*/
	SND_SOC_DAPM_PGA("MIC1 PGA", ADC_SRCBST_CTRL, MIC1AMPEN, 0, NULL, 0),
	SND_SOC_DAPM_PGA("MIC2 PGA", ADC_SRCBST_CTRL, MIC2AMPEN, 0, NULL, 0),

	SND_SOC_DAPM_PGA("LINEIN PGA", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MUX("MIC2 SRC", SND_SOC_NOPM, 0, 0, &mic2src_mux),

	SND_SOC_DAPM_MIXER("Line Out Mixer", LOUT_CTRL, LINEOUTEN, 0,
		lineout_mix_controls, ARRAY_SIZE(lineout_mix_controls)),

	/*INPUT widget*/
	SND_SOC_DAPM_INPUT("MIC1P"),
	SND_SOC_DAPM_INPUT("MIC1N"),

	SND_SOC_DAPM_MICBIAS("MainMic Bias", ADC_APC_CTRL, MBIASEN, 0),
	SND_SOC_DAPM_MICBIAS("HMic Bias", ADC_APC_CTRL, HBIASEN, 0),
	SND_SOC_DAPM_INPUT("MIC2"),
	SND_SOC_DAPM_INPUT("MIC3"),

	SND_SOC_DAPM_INPUT("LINEINP"),
	SND_SOC_DAPM_INPUT("LINEINN"),

	SND_SOC_DAPM_INPUT("AXIR"),
	SND_SOC_DAPM_INPUT("AXIL"),
	SND_SOC_DAPM_INPUT("D_MIC"),
	/*aif1 interface*/
	SND_SOC_DAPM_AIF_IN_E("AIF1DACL", "AIF1 Playback",
		0, SND_SOC_NOPM, 0, 0, ac100_aif1clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_IN_E("AIF1DACR", "AIF1 Playback",
		0, SND_SOC_NOPM, 0, 0, ac100_aif1clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("AIF1ADCL", "AIF1 Capture",
		0, SND_SOC_NOPM, 0, 0, ac100_aif1clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_OUT_E("AIF1ADCR", "AIF1 Capture",
		0, SND_SOC_NOPM, 0, 0, ac100_aif1clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*aif2 interface*/
	SND_SOC_DAPM_AIF_IN_E("AIF2DACL", "AIF2 Playback",
		0, SND_SOC_NOPM, 0, 0, ac100_aif2clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_IN_E("AIF2DACR", "AIF2 Playback",
		0, SND_SOC_NOPM, 0, 0, ac100_aif2clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("AIF2ADCL", "AIF2 Capture",
		0, SND_SOC_NOPM, 0, 0, ac100_aif2clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_OUT_E("AIF2ADCR", "AIF2 Capture",
		0, SND_SOC_NOPM, 0, 0, ac100_aif2clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*aif3 interface*/
	SND_SOC_DAPM_AIF_OUT_E("AIF3OUT", "AIF3 Capture",
		0, SND_SOC_NOPM, 0, 0, ac100_aif3clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_IN_E("AIF3IN", "AIF3 Playback",
		0, SND_SOC_NOPM, 0, 0, ac100_aif3clk,
		SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	/*headphone*/
	SND_SOC_DAPM_HP("Headphone", ac100_headphone_event),
	/*speaker*/
	SND_SOC_DAPM_SPK("External Speaker", ac100_speaker_event),
	/*earpiece*/
	SND_SOC_DAPM_SPK("Earpiece", ac100_earpiece_event),
	/*lineout*/
	SND_SOC_DAPM_LINE("Lineout", NULL),

	/*DMIC*/
	SND_SOC_DAPM_MUX("ADCL Mux", SND_SOC_NOPM, 0, 0, &adcl_mux),
	SND_SOC_DAPM_MUX("ADCR Mux", SND_SOC_NOPM, 0, 0, &adcr_mux),

	SND_SOC_DAPM_PGA_E("DMICL VIR", SND_SOC_NOPM, 0, 0, NULL, 0,
		dmic_mux_ev, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_PGA_E("DMICR VIR", SND_SOC_NOPM, 0, 0, NULL, 0,
		dmic_mux_ev, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
};

static const struct snd_soc_dapm_route ac100_dapm_routes[] = {
	{"AIF1ADCL", NULL, "AIF1OUT0L Mux"},
	{"AIF1ADCR", NULL, "AIF1OUT0R Mux"},

	{"AIF1ADCL", NULL, "AIF1OUT1L Mux"},
	{"AIF1ADCR", NULL, "AIF1OUT1R Mux"},

	/* aif1out0 mux 11---13*/
	{"AIF1OUT0L Mux", "AIF1_AD0L", "AIF1 AD0L Mixer"},
	{"AIF1OUT0L Mux", "AIF1_AD0R", "AIF1 AD0R Mixer"},

	{"AIF1OUT0R Mux", "AIF1_AD0R", "AIF1 AD0R Mixer"},
	{"AIF1OUT0R Mux", "AIF1_AD0L", "AIF1 AD0L Mixer"},

	/*AIF1OUT1 mux 11--13 */
	{"AIF1OUT1L Mux", "AIF1_AD1L", "AIF1 AD1L Mixer"},
	{"AIF1OUT1L Mux", "AIF1_AD1R", "AIF1 AD1R Mixer"},

	{"AIF1OUT1R Mux", "AIF1_AD1R", "AIF1 AD1R Mixer"},
	{"AIF1OUT1R Mux", "AIF1_AD1L", "AIF1 AD1L Mixer"},

	/*AIF1 AD0L Mixer*/
	{"AIF1 AD0L Mixer", "AIF1 DA0L Switch", "AIF1IN0L Mux"},
	{"AIF1 AD0L Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	{"AIF1 AD0L Mixer", "ADCL Switch", "ADCL Mux"},
	{"AIF1 AD0L Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},

	/*AIF1 AD0R Mixer*/
	{"AIF1 AD0R Mixer", "AIF1 DA0R Switch", "AIF1IN0R Mux"},
	{"AIF1 AD0R Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},
	{"AIF1 AD0R Mixer", "ADCR Switch", "ADCR Mux"},
	{"AIF1 AD0R Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},

	/*AIF1 AD1L Mixer*/
	{"AIF1 AD1L Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	{"AIF1 AD1L Mixer", "ADCL Switch", "ADCL Mux"},
	/*AIF1 AD1R Mixer*/
	{"AIF1 AD1R Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},
	{"AIF1 AD1R Mixer", "ADCR Switch", "ADCR Mux"},
	/*AIF1 DA0 IN 12h*/
	{"AIF1IN0L Mux", "AIF1_DA0L", "AIF1DACL"},
	{"AIF1IN0L Mux", "AIF1_DA0R", "AIF1DACR"},

	{"AIF1IN0R Mux", "AIF1_DA0R", "AIF1DACR"},
	{"AIF1IN0R Mux", "AIF1_DA0L", "AIF1DACL"},

	/*AIF1 DA1 IN 12h*/
	{"AIF1IN1L Mux", "AIF1_DA1L", "AIF1DACL"},
	{"AIF1IN1L Mux", "AIF1_DA1R", "AIF1DACR"},

	{"AIF1IN1R Mux", "AIF1_DA1R", "AIF1DACR"},
	{"AIF1IN1R Mux", "AIF1_DA1L", "AIF1DACL"},

	/*aif2 virtual*/
	{"AIF2INL Mux switch", "aif2inl aif2Switch", "AIF2INL Mux"},
	{"AIF2INR Mux switch", "aif2inr aif2Switch", "AIF2INR Mux"},

	{"AIF2INL_VIR", NULL, "AIF2INL Mux switch"},
	{"AIF2INR_VIR", NULL, "AIF2INR Mux switch"},

	{"AIF2INL_VIR", NULL, "AIF2INL Mux VIR"},
	{"AIF2INR_VIR", NULL, "AIF2INR Mux VIR"},

	/*4c*/
	{"DACL Mixer", "AIF1DA0L Switch", "AIF1IN0L Mux"},
	{"DACL Mixer", "AIF1DA1L Switch", "AIF1IN1L Mux"},

	{"DACL Mixer", "ADCL Switch", "ADCL Mux"},
	{"DACL Mixer", "AIF2DACL Switch", "AIF2INL_VIR"},
	{"DACR Mixer", "AIF1DA0R Switch", "AIF1IN0R Mux"},
	{"DACR Mixer", "AIF1DA1R Switch", "AIF1IN1R Mux"},

	{"DACR Mixer", "ADCR Switch", "ADCR Mux"},
	{"DACR Mixer", "AIF2DACR Switch", "AIF2INR_VIR"},

	{"Right Output Mixer", "DACR Switch", "DACR Mixer"},
	{"Right Output Mixer", "DACL Switch", "DACL Mixer"},

	{"Right Output Mixer", "AUXINR Switch", "AXIR"},
	{"Right Output Mixer", "LINEINR Switch", "LINEINN"},
	{"Right Output Mixer", "LINEINL-LINEINR Switch", "LINEIN PGA"},
	{"Right Output Mixer", "MIC2Booststage Switch", "MIC2 PGA"},
	{"Right Output Mixer", "MIC1Booststage Switch", "MIC1 PGA"},

	{"Left Output Mixer", "DACL Switch", "DACL Mixer"},
	{"Left Output Mixer", "DACR Switch", "DACR Mixer"},

	{"Left Output Mixer", "AUXINL Switch", "AXIL"},
	{"Left Output Mixer", "LINEINL Switch", "LINEINP"},
	{"Left Output Mixer", "LINEINL-LINEINR Switch", "LINEIN PGA"},
	{"Left Output Mixer", "MIC2Booststage Switch", "MIC2 PGA"},
	{"Left Output Mixer", "MIC1Booststage Switch", "MIC1 PGA"},

	/*hp mux*/
	{"HP_R Mux", "DACR HPR Switch", "DACR Mixer"},
	{"HP_R Mux", "Right Analog Mixer HPR Switch", "Right Output Mixer"},

	{"HP_L Mux", "DACL HPL Switch", "DACL Mixer"},
	{"HP_L Mux", "Left Analog Mixer HPL Switch", "Left Output Mixer"},

	/*hp endpoint*/
	{"HPOUTR", NULL, "HP_R Mux"},
	{"HPOUTL", NULL, "HP_L Mux"},

	{"Headphone", NULL, "HPOUTR"},
	{"Headphone", NULL, "HPOUTL"},

	/*External Speaker*/
	{"External Speaker", NULL, "SPK1P"},
	{"External Speaker", NULL, "SPK1N"},

	{"External Speaker", NULL, "SPK2P"},
	{"External Speaker", NULL, "SPK2N"},

	/*spk mux*/
	{"SPK_LR Adder", NULL, "Right Output Mixer"},
	{"SPK_LR Adder", NULL, "Left Output Mixer"},

	{"SPK_L Mux", "MIXL MIXR  Switch", "SPK_LR Adder"},
	{"SPK_L Mux", "MIXEL Switch", "Left Output Mixer"},

	{"SPK_R Mux", "MIXR MIXL Switch", "SPK_LR Adder"},
	{"SPK_R Mux", "MIXER Switch", "Right Output Mixer"},

	{"SPK1P", NULL, "SPK_R Mux"},
	{"SPK1N", NULL, "SPK_R Mux"},

	{"SPK2P", NULL, "SPK_L Mux"},
	{"SPK2N", NULL, "SPK_L Mux"},

	/*earpiece mux*/
	{"EAR Mux", "DACR", "DACR Mixer"},
	{"EAR Mux", "DACL", "DACL Mixer"},
	{"EAR Mux", "Right Analog Mixer", "Right Output Mixer"},
	{"EAR Mux", "Left Analog Mixer", "Left Output Mixer"},
	{"EAROUTP", NULL, "EAR Mux"},
	{"EAROUTN", NULL, "EAR Mux"},
	{"Earpiece", NULL, "EAROUTP"},
	{"Earpiece", NULL, "EAROUTN"},

	/*LADC SOURCE mixer*/
	{"LEFT ADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"LEFT ADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"LEFT ADC input Mixer", "LININL-R Switch", "LINEIN PGA"},
	{"LEFT ADC input Mixer", "LINEINL Switch", "LINEINN"},
	{"LEFT ADC input Mixer", "AUXINL Switch", "AXIL"},
	{"LEFT ADC input Mixer", "Lout_Mixer_Switch", "Left Output Mixer"},
	{"LEFT ADC input Mixer", "Rout_Mixer_Switch", "Right Output Mixer"},

	/*RADC SOURCE mixer*/
	{"RIGHT ADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"RIGHT ADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"RIGHT ADC input Mixer", "LINEINL-R Switch", "LINEIN PGA"},
	{"RIGHT ADC input Mixer", "LINEINR Switch", "LINEINP"},
	{"RIGHT ADC input Mixer", "AUXINR Switch", "AXIR"},
	{"RIGHT ADC input Mixer", "Rout_Mixer_Switch", "Right Output Mixer"},
	{"RIGHT ADC input Mixer", "Lout_Mixer_Switch", "Left Output Mixer"},

	{"MIC1 PGA", NULL, "MIC1P"},
	{"MIC1 PGA", NULL, "MIC1N"},

	{"MIC2 PGA", NULL, "MIC2 SRC"},

	{"MIC2 SRC", "MIC2", "MIC2"},
	{"MIC2 SRC", "MIC3", "MIC3"},

	{"LINEIN PGA", NULL, "LINEINP"},
	{"LINEIN PGA", NULL, "LINEINN"},

	{"LINEOUTP", NULL, "Line Out Mixer"},
	{"LINEOUTN", NULL, "Line Out Mixer"},

	{"Lineout", NULL, "LINEOUTP"},
	{"Lineout", NULL, "LINEOUTN"},


	/*lineout*/
	{"Line Out Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"Line Out Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"Line Out Mixer", "Rout_Mixer_Switch", "Right Output Mixer"},
	{"Line Out Mixer", "Lout_Mixer_Switch", "Left Output Mixer"},

	/*AIF2 out */
	{"AIF2ADCL", NULL, "AIF2OUTL Mux"},
	{"AIF2ADCR", NULL, "AIF2OUTR Mux"},

	{"AIF2OUTL Mux", "AIF2_ADCL", "AIF2 ADL Mixer"},
	{"AIF2OUTL Mux", "AIF2_ADCR", "AIF2 ADR Mixer"},

	{"AIF2OUTR Mux", "AIF2_ADCR", "AIF2 ADR Mixer"},
	{"AIF2OUTR Mux", "AIF2_ADCL", "AIF2 ADL Mixer"},

	/*23*/
	{"AIF2 ADL Mixer", "AIF1 DA0L Switch", "AIF1IN0L Mux"},
	{"AIF2 ADL Mixer", "AIF1 DA1L Switch", "AIF1IN1L Mux"},
	{"AIF2 ADL Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},
	{"AIF2 ADL Mixer", "ADCL Switch", "ADCL Mux"},
	{"AIF2 ADR Mixer", "AIF1 DA0R Switch", "AIF1IN0R Mux"},
	{"AIF2 ADR Mixer", "AIF1 DA1R Switch", "AIF1IN1R Mux"},
	{"AIF2 ADR Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	{"AIF2 ADR Mixer", "ADCR Switch", "ADCR Mux"},

	/*aif2*/
	{"AIF2INL Mux", "AIF2_DACL", "AIF2DACL"},
	{"AIF2INL Mux", "AIF2_DACR", "AIF2DACR"},

	{"AIF2INR Mux", "AIF2_DACR", "AIF2DACR"},
	{"AIF2INR Mux", "AIF2_DACL", "AIF2DACL"},

	/*aif3*/
	{"AIF2INL Mux VIR switch", "aif2inl aif3Switch", "AIF3IN"},
	{"AIF2INR Mux VIR switch", "aif2inr aif3Switch", "AIF3IN"},

	{"AIF2INL Mux VIR", NULL, "AIF2INL Mux VIR switch"},
	{"AIF2INR Mux VIR", NULL, "AIF2INR Mux VIR switch"},

	{"AIF3OUT", NULL, "AIF3OUT Mux"},
	{"AIF3OUT Mux", "AIF2 ADC left channel", "AIF2 ADL Mixer"},
	{"AIF3OUT Mux", "AIF2 ADC right channel", "AIF2 ADR Mixer"},

	/*ADC--ADCMUX*/
	{"ADCR Mux", "ADC", "RIGHT ADC input Mixer"},
	{"ADCL Mux", "ADC", "LEFT ADC input Mixer"},

	/*DMIC*/
	{"ADCR Mux", "DMIC", "DMICR VIR"},
	{"ADCL Mux", "DMIC", "DMICL VIR"},

	{"DMICL VIR", NULL, "D_MIC"},
	{"DMICR VIR", NULL, "D_MIC"},
};

/* PLL divisors */
struct pll_div {
	unsigned int pll_in;
	unsigned int pll_out;
	int m;
	int n_i;
	int n_f;
};

struct aif1_fs {
	unsigned int samplerate;
	int aif1_bclk_bit;
	int aif1_srbit;
};

struct aif1_bclk {
	int aif1_bclk_div;
	int aif1_bclk_bit;
};

struct aif1_lrck {
	int aif1_lrck_div;
	int aif1_lrck_bit;
};

struct aif1_word_size {
	int aif1_wsize_val;
	int aif1_wsize_bit;
};

/*
* Note : pll code from original tdm/i2s driver.
* freq_out = freq_in * N/(m*(2k+1)) , k=1,N=N_i+N_f,N_f=factor*0.2;
*/
static const struct pll_div codec_pll_div[] = {
	{128000, 22579200, 1, 529, 1},
	{192000, 22579200, 1, 352, 4},
	{256000, 22579200, 1, 264, 3},
	{384000, 22579200, 1, 176, 2},/*((176+2*0.2)*6000000)/(38*(2*1+1))*/
	{6000000, 22579200, 38, 429, 0},/*((429+0*0.2)*6000000)/(38*(2*1+1))*/
	{13000000, 22579200, 19, 99, 0},
	{19200000, 22579200, 25, 88, 1},
	{24000000, 22579200, 38, 107, 1},
	{128000, 24576000, 1, 576, 0},
	{192000, 24576000, 1, 384, 0},
	{256000, 24576000, 1, 288, 0},
	{384000, 24576000, 1, 192, 0},
	{2048000, 24576000, 1, 36, 0},
	{1024000, 24576000, 1, 72, 0},
	{3072000, 24576000, 1, 24, 0},
	{6000000, 24576000, 25, 307, 1},
	{13000000, 24576000, 42, 238, 1},
	{19200000, 24576000, 25, 88, 1},
	{24000000, 24576000, 25, 76, 4},
};

/*for all of the fs freq. lrck_div is 64*/
static const struct aif1_fs codec_aif1_fs[] = {
	{44100, 4, 7},
	{48000, 4, 8},
	{8000, 9, 0},
	{11025, 8, 1},
	{12000, 8, 2},
	{16000, 7, 3},
	{22050, 6, 4},
	{24000, 6, 5},
	{32000, 5, 6},
	{96000, 2, 9},
	{192000, 1, 10},
};

static const struct aif1_bclk codec_aif1_bclk[] = {
	{1, 0},
	{2, 1},
	{4, 2},
	{6, 3},
	{8, 4},
	{12, 5},
	{16, 6},
	{24, 7},
	{32, 8},
	{48, 9},
	{64, 10},
	{96, 11},
	{128, 12},
	{192, 13},
};

static const struct aif1_lrck codec_aif1_lrck[] = {
	{16, 0},
	{32, 1},
	{64, 2},
	{128, 3},
	{256, 4},
};

static const struct aif1_word_size codec_aif1_wsize[] = {
	{8, 0},
	{16, 1},
	{20, 2},
	{24, 3},
};

static int ac100_aif_mute(struct snd_soc_dai *codec_dai, int mute)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->mute_mutex);
	if (mute) {
		if (ac100->aif2_mute == 0)
			snd_soc_write(codec, DAC_VOL_CTRL, 0);
	} else {
		snd_soc_write(codec, DAC_VOL_CTRL, 0xa0a0);
	}
	mutex_unlock(&ac100->mute_mutex);
	return 0;
}

static int ac100_aif2_mute(struct snd_soc_dai *codec_dai, int mute)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	mutex_lock(&ac100->mute_mutex);
	if (mute == 0) {
		snd_soc_write(codec, DAC_VOL_CTRL, 0xa0a0);
		ac100->aif2_mute = 1;
	} else
		ac100->aif2_mute = 0;
	mutex_unlock(&ac100->mute_mutex);
	return 0;
}

static void ac100_aif_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *codec_dai)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	int reg_val;

	AC100_DBG("%s,line:%d\n", __func__, __LINE__);
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		if (agc_used)
			agc_enable(codec, 0);

		reg_val = (snd_soc_read(codec, AIF_SR_CTRL) >> 12);
		reg_val &= 0xf;
		if (codec_dai->playback_active && dmic_used &&
			((reg_val == 0x4) || (reg_val == 0x5))) {
			snd_soc_update_bits(codec, AIF_SR_CTRL,
				(0xf<<AIF1_FS), (0x7<<AIF1_FS));
		}
	}
}

static int ac100_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int i = 0;
	int AIF_CLK_CTRL = 0;
	int aif1_word_size = 16;
	/*
	* 22.5792M/8 = 2.8224M;
	* 2.8224M/64 = 44.1k;
	*
	* 24.576M/8 = 3.072M;
	* 3.072M/64 = 48k;
	*/
	int aif1_bclk_div = 8;
	int aif1_lrck_div = 64;

	struct snd_soc_codec *codec = codec_dai->codec;

	switch (codec_dai->id) {
	case 1:
		AIF_CLK_CTRL = AIF1_CLK_CTRL;
		aif1_lrck_div = 64;
		break;
	case 2:
		AIF_CLK_CTRL = AIF2_CLK_CTRL;
		aif1_lrck_div = 64;
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_bclk); i++) {
		if (codec_aif1_bclk[i].aif1_bclk_div == aif1_bclk_div) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0xf<<AIF1_BCLK_DIV),
				((codec_aif1_bclk[i].aif1_bclk_bit)
				 <<AIF1_BCLK_DIV));
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_lrck); i++) {
		if (codec_aif1_lrck[i].aif1_lrck_div == aif1_lrck_div) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x7<<AIF1_LRCK_DIV),
				((codec_aif1_lrck[i].aif1_lrck_bit)
				 <<AIF1_LRCK_DIV));
			break;
		}
	}
	/*for all of the fs freq. lrck_div is 64*/
	for (i = 0; i < ARRAY_SIZE(codec_aif1_fs); i++) {
		if (codec_aif1_fs[i].samplerate ==  params_rate(params)) {
			if (codec_dai->capture_active && dmic_used &&
				codec_aif1_fs[i].samplerate == 44100)
				snd_soc_update_bits(codec, AIF_SR_CTRL,
					(0xf<<AIF1_FS), (0x4<<AIF1_FS));
			else if (codec_dai->capture_active && dmic_used &&
				codec_aif1_fs[i].samplerate == 48000)
				snd_soc_update_bits(codec, AIF_SR_CTRL,
					(0xf<<AIF1_FS), (0x5<<AIF1_FS));
			else
				snd_soc_update_bits(codec, AIF_SR_CTRL,
					(0xf<<AIF1_FS),
					((codec_aif1_fs[i].aif1_srbit)
					 <<AIF1_FS));

			snd_soc_update_bits(codec, AIF_SR_CTRL, (0xf<<AIF2_FS),
				((codec_aif1_fs[i].aif1_srbit)<<AIF2_FS));
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0xf<<AIF1_BCLK_DIV),
				((codec_aif1_fs[i].aif1_bclk_bit)
				 <<AIF1_BCLK_DIV));
			break;
		}
	}
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S32_LE:
		aif1_word_size = 24;
	break;
	case SNDRV_PCM_FORMAT_S16_LE:
	default:
		aif1_word_size = 16;
	break;
	}
	for (i = 0; i < ARRAY_SIZE(codec_aif1_wsize); i++) {
		if (codec_aif1_wsize[i].aif1_wsize_val == aif1_word_size) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x3<<AIF1_WORK_SIZ),
				((codec_aif1_wsize[i].aif1_wsize_bit)
				 <<AIF1_WORK_SIZ));
			break;
		}
	}

	return 0;
}

static int ac100_set_dai_sysclk(struct snd_soc_dai *codec_dai,
	int clk_id, unsigned int freq, int dir)
{
	struct snd_soc_codec *codec = codec_dai->codec;

	switch (clk_id) {
	case AIF1_CLK:
		AC100_DBG("%s,line:%d,snd_soc_read(SYSCLK_CTRL):%x\n",
			__func__, __LINE__,
			snd_soc_read(codec, SYSCLK_CTRL));
		/*system clk from aif1*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x1<<SYSCLK_SRC), (0x0<<SYSCLK_SRC));
		break;
	case AIF2_CLK:
		/*system clk from aif2*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x1<<SYSCLK_SRC), (0x1<<SYSCLK_SRC));
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int ac100_set_clkdiv(struct snd_soc_dai *dai,
	int clk_id, int clk_div)
{
	return 0;
}

static int ac100_set_dai_fmt(struct snd_soc_dai *codec_dai,
	unsigned int fmt)
{
	int reg_val;
	int AIF_CLK_CTRL = 0;
	struct snd_soc_codec *codec = codec_dai->codec;

	switch (codec_dai->id) {
	case 1:
		AC100_DBG("%s,line:%d\n", __func__, __LINE__);
		AIF_CLK_CTRL = AIF1_CLK_CTRL;
		break;
	case 2:
		AC100_DBG("%s,line:%d\n", __func__, __LINE__);
		AIF_CLK_CTRL = AIF2_CLK_CTRL;
		break;
	default:
		return -EINVAL;
	}
	AC100_DBG("%s,line:%d\n", __func__, __LINE__);

	/*
	* master or slave selection
	* 0 = Master mode
	* 1 = Slave mode
	*/
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	reg_val &= ~(0x1<<AIF1_MSTR_MOD);
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM: /* codec clk & frm master */
		reg_val |= (0x0<<AIF1_MSTR_MOD);
		break;
	case SND_SOC_DAIFMT_CBS_CFS: /* codec clk & frm slave */
		reg_val |= (0x1<<AIF1_MSTR_MOD);
		break;
	default:
		pr_err("unknwon master/slave format\n");
		return -EINVAL;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	/* i2s mode selection */
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	reg_val &= ~(3<<AIF1_DATA_FMT);
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S: /* I2S1 mode */
		reg_val |= (0x0<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_RIGHT_J: /* Right Justified mode */
		reg_val |= (0x2<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_LEFT_J: /* Left Justified mode */
		reg_val |= (0x1<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_DSP_A: /* L reg_val msb after FRM LRC */
		reg_val |= (0x3<<AIF1_DATA_FMT);
		break;
	default:
		pr_err("%s, line:%d\n", __func__, __LINE__);
		return -EINVAL;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	/* DAI signal inversions */
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF: /* normal bit clock + nor frame */
		reg_val &= ~(0x1<<AIF1_LRCK_INV);
		reg_val &= ~(0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_NB_IF: /* normal bclk + inv frm */
		reg_val |= (0x1<<AIF1_LRCK_INV);
		reg_val &= ~(0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_NF: /* invert bclk + nor frm */
		reg_val &= ~(0x1<<AIF1_LRCK_INV);
		reg_val |= (0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_IF: /* invert bclk + inv frm */
		reg_val |= (0x1<<AIF1_LRCK_INV);
		reg_val |= (0x1<<AIF1_BCLK_INV);
		break;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	return 0;
}

static int ac100_set_fll(struct snd_soc_dai *codec_dai, int pll_id, int source,
	unsigned int freq_in, unsigned int freq_out)
{
	int i = 0;
	int m = 0;
	int n_i = 0;
	int n_f = 0;

	struct snd_soc_codec *codec = codec_dai->codec;

	AC100_DBG("%s, line:%d, pll_id:%d\n", __func__, __LINE__, pll_id);
	if (!freq_out)
		return 0;
	if ((freq_in < 128000) || (freq_in > 24576000)) {
		return -EINVAL;
	} else if ((freq_in == 24576000) || (freq_in == 22579200)) {
		switch (pll_id) {
		case AC100_MCLK1:
			/*select aif1 clk source from mclk1*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF1CLK_SRC), (0x0<<AIF1CLK_SRC));
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF2CLK_SRC), (0x0<<AIF2CLK_SRC));
			break;
		case AC100_MCLK2:
			/*select aif1 clk source from mclk2*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF1CLK_SRC), (0x1<<AIF1CLK_SRC));
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF2CLK_SRC), (0x1<<AIF2CLK_SRC));
			break;
		case AC100_BCLK1:
			/*select aif1 clk source from mclk2*/
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF1CLK_SRC), (0x3<<AIF1CLK_SRC));
			snd_soc_update_bits(codec, SYSCLK_CTRL,
				(0x3<<AIF2CLK_SRC), (0x3<<AIF2CLK_SRC));
			break;
		default:
			return -EINVAL;

		}
	//	return 0;
	}
	switch (pll_id) {
	case AC100_MCLK1:
		/*pll source from MCLK1*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x3<<PLLCLK_SRC), (0x0<<PLLCLK_SRC));
		break;
	case AC100_MCLK2:
		/*pll source from MCLK2*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x3<<PLLCLK_SRC), (0x1<<PLLCLK_SRC));
		break;
	case AC100_BCLK1:
		/*pll source from BCLK1*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x3<<PLLCLK_SRC), (0x2<<PLLCLK_SRC));
		break;
	case AC100_BCLK2:
		/*pll source from BCLK2*/
		snd_soc_update_bits(codec, SYSCLK_CTRL,
			(0x3<<PLLCLK_SRC), (0x3<<PLLCLK_SRC));
		break;
	default:
		return -EINVAL;
	}
	/* freq_out = freq_in * n/(m*(2k+1)) , k=1,N=N_i+N_f */
	for (i = 0; i < ARRAY_SIZE(codec_pll_div); i++) {
		if ((codec_pll_div[i].pll_in == freq_in) &&
			(codec_pll_div[i].pll_out == freq_out)) {
			m = codec_pll_div[i].m;
			n_i = codec_pll_div[i].n_i;
			n_f = codec_pll_div[i].n_f;
			break;
		}
	}
	AC100_DBG("%s, line:%d, pll_id:%d\n", __func__, __LINE__, pll_id);
	/*config pll m*/
	snd_soc_update_bits(codec, PLL_CTRL1,
		(0x3f<<PLL_POSTDIV_M), (m<<PLL_POSTDIV_M));
	/*config pll n*/
	snd_soc_update_bits(codec, PLL_CTRL2,
		(0x3ff<<PLL_PREDIV_NI), (n_i<<PLL_PREDIV_NI));
	snd_soc_update_bits(codec, PLL_CTRL2,
		(0x7<<PLL_POSTDIV_NF), (n_f<<PLL_POSTDIV_NF));
	snd_soc_update_bits(codec, PLL_CTRL2, (0x1<<PLL_EN), (1<<PLL_EN));
	/*enable pll_enable*/
	snd_soc_update_bits(codec, SYSCLK_CTRL,
		(0x1<<PLLCLK_ENA), (1<<PLLCLK_ENA));
	snd_soc_update_bits(codec, SYSCLK_CTRL,
		(0x3<<AIF1CLK_SRC), (0x3<<AIF1CLK_SRC));
	snd_soc_update_bits(codec, SYSCLK_CTRL,
		(0x3<<AIF2CLK_SRC), (0x3<<AIF2CLK_SRC));

	return 0;
}

static int ac100_audio_startup(struct snd_pcm_substream *substream,
	struct snd_soc_dai *codec_dai)
{
	struct snd_soc_codec *codec = codec_dai->codec;

	AC100_DBG("%s,line:%d\n", __func__, __LINE__);
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE && agc_used)
		agc_enable(codec, 1);

	return 0;
}

static int ac100_aif2_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int i = 0;
	int AIF_CLK_CTRL = 0;
	int aif1_word_size = 16;
	int aif1_bclk_div = aif2_bclk_div;/*aif2_bclk_div=8, 24.576M/8=3.072M*/
	int aif1_lrck_div = aif2_lrck_div;/*aif2_lrck_div=64, 3.072M/64=48k*/
	struct snd_soc_codec *codec = codec_dai->codec;

	switch (codec_dai->id) {
	case 1:
		AIF_CLK_CTRL = AIF1_CLK_CTRL;
		break;
	case 2:
		AIF_CLK_CTRL = AIF2_CLK_CTRL;
		break;
	default:
	return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_bclk); i++) {
		if (codec_aif1_bclk[i].aif1_bclk_div == aif1_bclk_div) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0xf<<AIF1_BCLK_DIV),
				((codec_aif1_bclk[i].aif1_bclk_bit)
				 <<AIF1_BCLK_DIV));
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_lrck); i++) {
		if (codec_aif1_lrck[i].aif1_lrck_div == aif1_lrck_div) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x7<<AIF1_LRCK_DIV),
				((codec_aif1_lrck[i].aif1_lrck_bit)
				 <<AIF1_LRCK_DIV));
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(codec_aif1_fs); i++) {
		if (codec_aif1_fs[i].samplerate ==  params_rate(params)) {
			snd_soc_update_bits(codec, AIF_SR_CTRL, (0xf<<AIF1_FS),
				((codec_aif1_fs[i].aif1_srbit)<<AIF1_FS));
			snd_soc_update_bits(codec, AIF_SR_CTRL, (0xf<<AIF2_FS),
				((codec_aif1_fs[i].aif1_srbit)<<AIF2_FS));
			break;
		}
	}
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S32_LE:
		aif1_word_size = 24;
	break;
	case SNDRV_PCM_FORMAT_S16_LE:
	default:
		aif1_word_size = 16;
	break;
	}
	for (i = 0; i < ARRAY_SIZE(codec_aif1_wsize); i++) {
		if (codec_aif1_wsize[i].aif1_wsize_val == aif1_word_size) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x3<<AIF1_WORK_SIZ),
				((codec_aif1_wsize[i].aif1_wsize_bit)
				 <<AIF1_WORK_SIZ));
			break;
		}
	}
	if (params_channels(params) == 1)
		snd_soc_update_bits(codec, AIF_CLK_CTRL, (0x1<<1), (0x1<<1));
	else
		snd_soc_update_bits(codec, AIF_CLK_CTRL, (0x1<<1), (0x1<<0));

	return 0;
}

static int ac100_aif3_set_dai_fmt(struct snd_soc_dai *codec_dai,
			       unsigned int fmt)
{
	int reg_val;
	struct snd_soc_codec *codec = codec_dai->codec;

	AC100_DBG("%s,line:%d\n", __func__, __LINE__);
	/* DAI signal inversions */
	reg_val = snd_soc_read(codec, AIF3_CLK_CTRL);
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF: /* normal bit clock + nor frame */
		reg_val &= ~(0x1<<AIF3_LRCK_INV);
		reg_val &= ~(0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_NB_IF: /* normal bclk + inv frm */
		reg_val |= (0x1<<AIF3_LRCK_INV);
		reg_val &= ~(0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_NF: /* invert bclk + nor frm */
		reg_val &= ~(0x1<<AIF3_LRCK_INV);
		reg_val |= (0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_IF: /* invert bclk + inv frm */
		reg_val |= (0x1<<AIF3_LRCK_INV);
		reg_val |= (0x1<<AIF3_BCLK_INV);
		break;
	}
	snd_soc_write(codec, AIF3_CLK_CTRL, reg_val);

	return 0;
}

static int ac100_aif3_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int aif3_word_size = 0;
	int aif3_size = 0;
	struct snd_soc_codec *codec = codec_dai->codec;
	/*config aif3clk from aif2clk*/
	snd_soc_update_bits(codec, AIF3_CLK_CTRL,
		(0x3<<AIF3_CLOC_SRC), (0x1<<AIF3_CLOC_SRC));
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
	/*case SNDRV_PCM_FORMAT_S32_LE:*/
		aif3_word_size = 24;
		aif3_size = 3;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
	default:
		aif3_word_size = 16;
		aif3_size = 1;
		break;
	}
	snd_soc_update_bits(codec, AIF3_CLK_CTRL,
		(0x3<<AIF3_WORD_SIZ), aif3_size<<AIF3_WORD_SIZ);
	return 0;
}

/*
**switch_hw_config:config the 53 codec register
*/
static void switch_hw_config(struct snd_soc_codec *codec)
{
	/*HMIC/MMIC BIAS voltage level select:2.5v*/
	snd_soc_update_bits(codec, OMIXER_BST1_CTRL,
		(0xf<<BIASVOLTAGE), (0xf<<BIASVOLTAGE));
	/*debounce when Key down or keyup*/
	snd_soc_update_bits(codec, HMIC_CTRL1,
				(0xf << HMIC_M), (0x0 << HMIC_M));
	/*debounce when earphone plugin or pullout*/
	snd_soc_update_bits(codec, HMIC_CTRL1,
				(0xf << HMIC_N), (0x4 << HMIC_N));
	snd_soc_update_bits(codec, HMIC_CTRL2,
				(0x3 << HMIC_SF), (0x0 << HMIC_SF));
	/*Down Sample Setting Select/11:Downby 8,16Hz*/
	snd_soc_update_bits(codec, HMIC_CTRL2,
				(0x3<<HMIC_SAMPLE_SELECT),
				(0x0<<HMIC_SAMPLE_SELECT));
	/*Hmic_th2 for detecting Keydown or Keyup.*/
	snd_soc_update_bits(codec, HMIC_CTRL2,
		(0x1f<<HMIC_TH2), (0x8<<HMIC_TH2));


    /*Hmic_th1[4:0],detecting eraphone plugin or pullout*/
	/* fix: occur irq after record sound */
	snd_soc_update_bits(codec, HMIC_CTRL2,
		(0x1f<<HMIC_TH1), (0x3<<HMIC_TH1));
	/*Hmic_th1*/
	snd_soc_update_bits(codec, HMIC_CTRL1,
		(0x3 << HMIC_TH1_HYSTERESIS), (0x3<<HMIC_TH1_HYSTERESIS));

	/* keyup irq pending bit auto clear when keydown irq */
	snd_soc_update_bits(codec, HMIC_CTRL2,
		(0x1 << KEYUP_CLEAR), (0x1 << KEYUP_CLEAR));

	/*Clear Irq Pending*/
	snd_soc_update_bits(codec, HMIC_STS,
			(0x1f << HMIC_DATA_PEND),
			(0x1f << HMIC_DATA_PEND));

	/*Headset microphone BIAS Enable*/
	snd_soc_update_bits(codec, ADC_APC_CTRL,
		(0x1<<HBIASEN), (0x1<<HBIASEN));
	/*Headset microphone BIAS Current sensor & ADC Enable*/
	snd_soc_update_bits(codec, ADC_APC_CTRL,
		(0x1<<HBIASADCEN), (0x1<<HBIASADCEN));

	/*Earphone Plugin/out Irq Enable*/
	snd_soc_update_bits(codec, HMIC_CTRL1,
		(0x1<<HMIC_PULLOUT_IRQ),
		(0x1<<HMIC_PULLOUT_IRQ));
	snd_soc_update_bits(codec, HMIC_CTRL1,
		(0x1<<HMIC_PLUGIN_IRQ),
		(0x1<<HMIC_PLUGIN_IRQ));

	snd_soc_update_bits(codec, HMIC_CTRL1,
		(0x1<<HMIC_DATA_IRQ_EN),
		(0x1<<HMIC_DATA_IRQ_EN));

	/*Hmic KeyUp/key down Irq Enable*/
	snd_soc_update_bits(codec, HMIC_CTRL1,
		(0x1<<HMIC_KEYDOWN_IRQ),
		(0x1<<HMIC_KEYDOWN_IRQ));

	/*headphone calibration clock frequency select*/
	snd_soc_update_bits(codec, SPKOUT_CTRL,
		(0x7<<HPCALICKS), (0x7<<HPCALICKS));
}

static int ac100_set_bias_level(struct snd_soc_codec *codec,
				      enum snd_soc_bias_level level)
{
	switch (level) {
	case SND_SOC_BIAS_ON:
		AC100_DBG("%s,line:%d, SND_SOC_BIAS_ON\n", __func__, __LINE__);
		break;
	case SND_SOC_BIAS_PREPARE:
		AC100_DBG("%s,line:%d, SND_SOC_BIAS_PREPARE\n",
			__func__, __LINE__);
		break;
	case SND_SOC_BIAS_STANDBY:
		switch_hw_config(codec);
		AC100_DBG("%s,line:%d, SND_SOC_BIAS_STANDBY\n",
			__func__, __LINE__);
		break;
	case SND_SOC_BIAS_OFF:
		snd_soc_update_bits(codec, ADC_APC_CTRL,
			(0x1<<HBIASEN), (0<<HBIASEN));
		snd_soc_update_bits(codec, ADC_APC_CTRL,
			(0x1<<HBIASADCEN), (0<<HBIASADCEN));
		snd_soc_update_bits(codec, OMIXER_DACA_CTRL,
			(0xf<<HPOUTPUTENABLE), (0<<HPOUTPUTENABLE));
		snd_soc_update_bits(codec, ADDA_TUNE3,
			(0x1<<OSCEN), (0<<OSCEN));
		AC100_DBG("%s,line:%d, SND_SOC_BIAS_OFF\n",
			__func__, __LINE__);
		break;
	}
	snd_soc_codec_init_bias_level(codec, level);
	return 0;
}
static const struct snd_soc_dai_ops ac100_aif1_dai_ops = {
	.set_sysclk = ac100_set_dai_sysclk,
	.set_clkdiv = ac100_set_clkdiv,
	.set_fmt = ac100_set_dai_fmt,
	.hw_params = ac100_hw_params,
	.shutdown = ac100_aif_shutdown,
	.digital_mute = ac100_aif_mute,
	.set_pll = ac100_set_fll,
	.startup = ac100_audio_startup,
};

static const struct snd_soc_dai_ops ac100_aif2_dai_ops = {
	.set_sysclk = ac100_set_dai_sysclk,
	.set_fmt = ac100_set_dai_fmt,
	.hw_params = ac100_aif2_hw_params,
	.shutdown = ac100_aif_shutdown,
	.set_pll = ac100_set_fll,
	.digital_mute = ac100_aif2_mute,
};

static const struct snd_soc_dai_ops ac100_aif3_dai_ops = {
	.hw_params = ac100_aif3_hw_params,
	.set_fmt = ac100_aif3_set_dai_fmt,
};

static struct snd_soc_dai_driver ac100_dai[] = {
	{
		.name = "ac100-aif1",
		.id = 1,
		.playback = {
			.stream_name = "AIF1 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		},
		.capture = {
			.stream_name = "AIF1 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		 },
		.ops = &ac100_aif1_dai_ops,
	},
	{
		.name = "ac100-aif2",
		.id = 2,
		.playback = {
			.stream_name = "AIF2 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		},
		.capture = {
			.stream_name = "AIF2 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		},
		.ops = &ac100_aif2_dai_ops,
	},
	{
		.name = "ac100-aif3",
		.id = 3,
		.playback = {
			.stream_name = "AIF3 Playback",
			.channels_min = 1,
			.channels_max = 1,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		},
		.capture = {
			.stream_name = "AIF3 Capture",
			.channels_min = 1,
			.channels_max = 1,
			.rates = ac100_RATES,
			.formats = ac100_FORMATS,
		 },
		.ops = &ac100_aif3_dai_ops,
	}
};
#if 0
/* Checks jack insertion and identifies the key type.*/
static void sunxi_check_switch(struct work_struct *work)
{
	int reg_val = 0;
	int hmic_data = 0;
	struct ac100_priv *ac100 =
	    container_of(work, struct ac100_priv,
			hs_detect_work.work);

	mutex_lock(&ac100->jack_mutex);
	reg_val = snd_soc_read(ac100->codec, HMIC_STS);
	hmic_data = (reg_val & 0x1f00) >> HMIC_DATA;

	if (((ac100->switch_status & SND_JACK_HEADSET)
		== SND_JACK_HEADSET)
		&& (reg_val & HMKC_KEYDOWN_PEND)) {
		if ((hmic_data >= 0x19)
			&& (reset_flag == 0)) {
			ac100->switch_status |= SND_JACK_BTN_0;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);
			ac100->switch_status &= ~SND_JACK_BTN_0;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);

			pr_warn("[%s] line=%d,hmic_data:0x%x,Hook\n",
					__func__, __LINE__, hmic_data);
			if (reset_flag)
				reset_flag--;
		} else if ((hmic_data < 0x19 && hmic_data >= 0x16)
			&& (reset_flag == 0)) {
			ac100->switch_status |= SND_JACK_BTN_1;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);
			ac100->switch_status &= ~SND_JACK_BTN_1;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);

			pr_warn("[%s] line=%d,hmic_data:0x%x,VOL++\n",
					__func__, __LINE__, hmic_data);
			if (reset_flag)
				reset_flag--;
		} else if ((hmic_data < 0x16 && hmic_data >= 0x10)
			&& (reset_flag == 0)) {
			ac100->switch_status |= SND_JACK_BTN_2;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);
			ac100->switch_status &= ~SND_JACK_BTN_2;
			snd_jack_report(ac100->jack.jack,
					ac100->switch_status);

			pr_warn("[%s] line=%d,hmic_data:0x%x,VOL--\n",
					__func__, __LINE__, hmic_data);

			if (reset_flag)
				reset_flag--;
		} else {
			/*This could be other key data,try fix it*/
			pr_debug("keydata:%x,Key data err\n",
				 reg_val);
		}
	} else {
		/* for headphone*/
	}

	/* Clear the key and hmic_data irq pending*/
	reg_val = snd_soc_read(ac100->codec, HMIC_STS);
	if ((reg_val & 0x1f) != 0) {
		reg_val |= (0x1f << 0);
		snd_soc_write(ac100->codec, HMIC_STS, reg_val);
	}

	mutex_unlock(&ac100->jack_mutex);
}

/*
* Identify the jack type as Headset/Headphone/None
*/
static int sunxi_check_jack_type(struct snd_soc_jack *jack)
{
	u32 reg_val = 0;
	unsigned int temp_value[11];
	u32 tempdata = 0;
	struct ac100_priv *ac100 = container_of(jack, struct ac100_priv, jack);

	mutex_lock(&ac100->jack_mutex);

	ac100->check_count = 0;
	ac100->check_count_sum = 0;

	for (;;) {
		msleep(30);
		/*read HMIC_DATA */
		reg_val = snd_soc_read(ac100->codec, HMIC_STS);
		reg_val = (reg_val>>HMIC_DATA);
		reg_val &= 0x1f;
		if (ac100->check_count_sum <= HEADSET_CHECKCOUNT_SUM) {
			if (ac100->check_count <= HEADSET_CHECKCOUNT) {
				temp_value[ac100->check_count] = reg_val;
				ac100->check_count++;
				if (ac100->check_count >= 2) {
					if (!(temp_value[
					ac100->check_count - 1] ==
					temp_value[
					(ac100->check_count) - 2])) {
					ac100->check_count = 0;
					ac100->check_count_sum = 0;
					}
				}
			} else {
				ac100->check_count_sum++;
			}
		} else {
			tempdata = temp_value[ac100->check_count-2];
			break;
		}
	}

	if (tempdata >= ac100->HEADSET_DATA) {
		/* headphone:3 */
		pr_err("[%s] line=%d, (SND_JACK_HEADPHONE)--\n-- ac100->HEADSET_DATA:0x%x, tempdata:0x%x\n",
			__func__, __LINE__,
		    ac100->HEADSET_DATA, tempdata);
		ac100->switch_status = SND_JACK_HEADPHONE;
		snd_jack_report(ac100->jack.jack, ac100->switch_status);
		ac100->check_count = 0;
		ac100->check_count_sum = 0;
		reset_flag = 0;
	} else if ((tempdata < ac100->HEADSET_DATA)
			&& (tempdata >= 0x1)) {
		/* headset:4 */
		pr_warn("[%s] line=%d, (SND_JACK_HEADSET)--\n-- ac100->HEADSET_DATA:0x%x, tempdata:0x%x\n",
			__func__, __LINE__,
		    ac100->HEADSET_DATA, tempdata);

		ac100->switch_status = SND_JACK_HEADSET;
		snd_jack_report(ac100->jack.jack, ac100->switch_status);
		ac100->check_count = 0;
		ac100->check_count_sum = 0;
		reset_flag = 0;
	} else {
		ac100->switch_status = 0;
		/*clear headset pulgout pending.*/
		snd_jack_report(ac100->jack.jack, ac100->switch_status);
		pr_warn("[%s] line:%d,HEADPHONE_IDLE\n",
				__func__, __LINE__);
		ac100->check_count = 0;
		ac100->check_count_sum = 0;
		reset_flag = 0;
	}

	reg_val = snd_soc_read(ac100->codec, HMIC_STS);
	/* for clearing plug on after plugin*/
	if (reg_val & HMIC_PULLOUT_PEND) {
		reg_val &= ~(0x1 << HMIC_PLUGIN_PEND);
		reg_val &= ~(0x1 << HMKC_KEYDOWN_PEND);
		reg_val &= ~(0x1 << HMIC_DATA_PEND);
		reg_val |= (0x1 << HMIC_PULLOUT_PEND);
		snd_soc_write(ac100->codec, HMIC_STS, reg_val);
	}

	mutex_unlock(&ac100->jack_mutex);
	return ac100->switch_status;
}

/*
**sunxi_jack_work: clear audiocodec pending and Record the interrupt.
*/
static void sunxi_jack_work(struct work_struct *work)
{
	int reg_val = 0;
	int jack_state = 0;
	struct ac100_priv *ac100 =
	    container_of(work, struct ac100_priv,
			hs_irq_work.work);
	struct snd_soc_codec *codec = ac100->codec;

	ac100->check_count = 0;
	ac100->check_count_sum = 0;

	jack_state = snd_soc_read(ac100->codec, HMIC_STS);
	pr_warn("[%s] line:%d, jack_state:0x%x\n",
		__func__, __LINE__, jack_state);
	/*headphone insert*/
	if (jack_state & (1 << HMIC_PLUGIN_PEND)) {
		reg_val = snd_soc_read(ac100->codec, HMIC_STS);
		reg_val |= 0x1 << HMIC_PLUGIN_PEND;
		reg_val &= ~(0x1 << HMKC_KEYDOWN_PEND);
		/* correct data */
		reg_val &= ~(0x1 << HMIC_DATA_PEND);
		snd_soc_write(ac100->codec, HMIC_STS, reg_val);
		ac100->detect_state = PLUG_IN;
		sunxi_check_jack_type(&ac100->jack);
	}

	schedule_delayed_work(&ac100->hs_detect_work,
		msecs_to_jiffies(60));

	mutex_lock(&ac100->jack_mutex);
	msleep(20);
	jack_state = snd_soc_read(codec, HMIC_STS);
	/*headphone insert*/
	if (!(jack_state >> HMIC_DATA) ||
		((jack_state & (1 << HMIC_PULLOUT_PEND))
			&& !(jack_state >> HMIC_DATA))) {
		reg_val = snd_soc_read(codec, HMIC_STS);
		snd_soc_write(codec, HMIC_STS, reg_val);
		ac100->detect_state = PLUG_OUT;

		reset_flag++;
		pr_err("[%s]====Earhpone PLUG_OUT====\n", __func__);

		ac100->switch_status = 0;
		/*clear headset pulgout pending.*/
		snd_jack_report(ac100->jack.jack, ac100->switch_status);

		ac100->check_count = 0;
		ac100->check_count_sum = 0;
		reset_flag = 0;
	}
	mutex_unlock(&ac100->jack_mutex);
}

/*
**sunxi_jack_irq:  the interrupt handlers
*/
static irqreturn_t sunxi_jack_irq(int irq, void *para)
{
	struct ac100_priv *ac100 = (struct ac100_priv *)para;
	bool ret = false;

	if (ac100 == NULL)
		return -EINVAL;

	pr_warn("[%s] ======line:%d======\n", __func__, __LINE__);

	ret = schedule_delayed_work(&ac100->hs_irq_work,
						msecs_to_jiffies(60));
	if (!ret)
		pr_err("[sunxi_jack_irq]add work struct failed!\n");
	return 0;
}
#endif

static void codec_resume_work(struct work_struct *work)
{
	struct ac100_priv *ac100 =
	    container_of(work, struct ac100_priv, codec_resume);
	struct snd_soc_codec *codec = ac100->codec;
	int ret = 0;
#if 0
	/* headset irq gpio */
	ac100->jack_irq = gpio_to_irq(ac100->jack_gpio);
	if (IS_ERR_VALUE(ac100->jack_irq))
		pr_warn("[AC100] map gpio to jack_irq failed, errno = %d\n",
			ac100->jack_irq);

	pr_err("[AC100] gpio [%d] map to jack_irq [%d] ok\n",
		ac100->jack_gpio, ac100->jack_irq);

	/* request jack_irq, set jack_irq type to high level trigger */
	ret = devm_request_irq(codec->dev, ac100->jack_irq, sunxi_jack_irq,
				IRQF_TRIGGER_FALLING, "SWTICH_EINT", ac100);
	if (IS_ERR_VALUE(ret))
		pr_warn("[AC100] request jack_irq %d failed, errno = %d\n",
			ac100->jack_irq, ret);

	gpio_set_debounce(ac100->jack_gpio, 1);

#endif
	ret = regulator_enable(ac100->vol_supply.avcc);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to enable regulator!\n",
			__func__, __LINE__);

	ret = regulator_enable(ac100->vol_supply.io1);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to enable regulator!\n",
			__func__, __LINE__);

	ret = regulator_enable(ac100->vol_supply.io2);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to enable regulator!\n",
			__func__, __LINE__);

	ret = regulator_enable(ac100->vol_supply.ldoin);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to enable regulator!\n",
			__func__, __LINE__);

	ret = regulator_enable(ac100->vol_supply.cpvdd);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to enable regulator!\n",
			__func__, __LINE__);

	msleep(50);
	pr_err("%s : %d \n", __func__, __LINE__);
	set_configuration(codec);
#if 0
	if (agc_used)
		agc_config(codec);
#endif
	if (drc_used)
		drc_config(codec);

	pr_err("%s : %d \n", __func__, __LINE__);
	/*enable this bit to prevent leakage from ldoin*/
	snd_soc_update_bits(codec, ADDA_TUNE3, (0x1<<OSCEN), (0x1<<OSCEN));
	if (spkgpio.used) {
		gpio_direction_output(spkgpio.gpio, 1);
		gpio_set_value(spkgpio.gpio, 0);
	}
	pr_err("%s : %d \n", __func__, __LINE__);
}

/***************************************************************************/
static ssize_t ac100_debug_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	static long val;
	static int flag;
	u8 reg, num, i = 0;
	u16 value_w;
	char str[256] = "";
	struct ac100_priv *ac100 = dev_get_drvdata(dev);

	if (kstrtol(buf, 16, &val) < 0)
		return 0;

	flag = (val >> 24) & 0xF;

	if (flag) {
		/*write*/
		reg = (val >> 16) & 0xFF;
		value_w =  val & 0xFFFF;
		snd_soc_write(ac100->codec, reg, value_w);
		pr_info("write 0x%x to reg:0x%x\n", value_w, reg);
	} else {
		char *p = str;
		int len;
		u16 value;

		reg = (val>>8) & 0xFF;
		num = val&0xff;
		pr_info("\n");
		pr_info("read:start add:0x%x,count:0x%x\n", reg, num);

		do {
			value = snd_soc_read(ac100->codec, reg);
			len = sprintf(p, "0x%x: 0x%04x ", reg, value);
			p += len;
			reg += 1;
			i++;

			if (i%4 == 0 || i == num) {
				pr_info("%s\n", str);
				p = str;
			}
		} while (i < num);

	}
	return count;
}

static ssize_t ac100_debug_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u8 i = 0;
	int count = 0;
	u16 value;
	u8 reg = 0x00;
	u8 num = 0xc0;
	struct ac100_priv *ac100 = dev_get_drvdata(dev);

	pr_info("--------------------help------------------------\n");
	pr_info("echo flag|reg|val > ac100\n");
	pr_info("eg read addr=0x06,count 0x10:echo 0610 >ac100\n");
	pr_info("eg write val:0x13fe to 0x06 :echo 10613fe > ac100\n");
	pr_info("------------------------------------------------\n");

	count += sprintf(buf+count, "read:start add:0x%x,count:0x%x\n",
		reg, num);

	do {
		value = snd_soc_read(ac100->codec, reg);
		count += sprintf(buf + count, "0x%x: 0x%04x ", reg, value);
		reg += 1;
		i++;

		if (i%4 == 0 || i == num)
			count += sprintf(buf + count, "\n");

	} while (i < num);

	return count;
}

static DEVICE_ATTR(ac100, 0644, ac100_debug_show, ac100_debug_store);

static struct attribute *audio_debug_attrs[] = {
	&dev_attr_ac100.attr,
	NULL,
};

static struct attribute_group audio_debug_attr_group = {
	.name   = "ac100_debug",
	.attrs  = audio_debug_attrs,
};

/************************************************************/
static int ac100_codec_probe(struct snd_soc_codec *codec)
{
	int ret = 0;
	unsigned int val;
	struct device_node *node = of_find_compatible_node(NULL, NULL, "allwinner,sunxi-ac100-codec");

	struct ac100_priv *ac100;
	struct snd_soc_dapm_context *dapm = snd_soc_codec_get_dapm(codec);
	pr_err("%s : %d \n", __func__, __LINE__);
	ac100 = dev_get_drvdata(codec->dev);
	if (ac100 == NULL)
		return -ENOMEM;

	ac100->codec = codec;
	snd_soc_codec_set_drvdata(codec, ac100);
#if 0
	/*ac100 jack driver*/
	ret = snd_soc_card_jack_new(codec->component.card, "sunxi Audio Jack",
				   SND_JACK_HEADSET | SND_JACK_BTN_0 |
				   SND_JACK_BTN_1 | SND_JACK_BTN_2,
				   &ac100->jack, NULL, 0);
	if (ret) {
		pr_err("jack creation failed\n");
		return ret;
	}

	snd_jack_set_key(ac100->jack.jack, SND_JACK_BTN_0, KEY_MEDIA);
	snd_jack_set_key(ac100->jack.jack, SND_JACK_BTN_1, KEY_VOLUMEUP);
	snd_jack_set_key(ac100->jack.jack, SND_JACK_BTN_2, KEY_VOLUMEDOWN);

	ac100->check_count = 0;
	ac100->check_count_sum = 0;

	/*
	*initial the parameters for judge switch state
	*/
	ac100->detect_state = PLUG_OUT;
	ac100->HEADSET_DATA = 0x15;
	INIT_DELAYED_WORK(&ac100->hs_detect_work, sunxi_check_switch);
	INIT_DELAYED_WORK(&ac100->hs_irq_work, sunxi_jack_work);
	mutex_init(&ac100->jack_mutex);

	/*
	* map the jack_irq of gpio
	* headphone gpio irq pin is ***
	* item_eint.gpio.gpio = ****;
	*/
	ac100->jack_irq = gpio_to_irq(ac100->jack_gpio);
	if (IS_ERR_VALUE(ac100->jack_irq)) {
		pr_warn("[AC100] map gpio to jack_irq failed, errno = %d\n",
			ac100->jack_irq);
		return -EINVAL;
	}

	pr_err("[AC100] gpio [%d] map to jack_irq [%d] ok\n",
		ac100->jack_gpio, ac100->jack_irq);

	/* request jack_irq, set jack_irq type to high level trigger */
	ret = devm_request_irq(codec->dev, ac100->jack_irq,
				sunxi_jack_irq,
				IRQF_TRIGGER_FALLING,
				"IRQ_AUDIO", ac100);
	if (IS_ERR_VALUE(ret)) {
		pr_err("[AC100] request jack_irq %d failed, errno = %d\n",
			ac100->jack_irq, ret);
		return -EINVAL;
	}

	ret = gpio_set_debounce(ac100->jack_gpio, 1);
	if (ret) {
		pr_err("[AC100]gpio_set_debouncefailed(ret:%d)\n", ret);
		return -EINVAL;
	}

	INIT_WORK(&ac100->codec_resume, codec_resume_work);
#endif
	pr_err("%s : %d \n", __func__, __LINE__);
	ac100->dac_enable = 0;
	ac100->adc_enable = 0;
	ac100->aif1_clken = 0;
	ac100->aif2_clken = 0;
	ac100->aif3_clken = 0;
	mutex_init(&ac100->dac_mutex);
	mutex_init(&ac100->adc_mutex);
	mutex_init(&ac100->aifclk_mutex);
	mutex_init(&ac100->mute_mutex);

	/*
	* config gpio info of audio_pa_ctrl,
	* the default pa config is close(check pa sys_config1.fex)
	*/
	if (spkgpio.used) {
		gpio_direction_output(spkgpio.gpio, 1);
		gpio_set_value(spkgpio.gpio, 0);
	}

	ret = of_property_read_u32(node, "aif2_lrck_div", &val);
	if (ret < 0) {
		dev_warn(codec->dev,
			"aif2_lrck_div config missing or invalid\n");
		aif2_lrck_div = 256;
	} else {
		aif2_lrck_div = val;
		pr_debug("aif2_lrck_div=%d\n", val);
	}

	ret = of_property_read_u32(node, "aif2_bclk_div", &val);
	if (ret < 0) {
		dev_warn(codec->dev,
			"aif2_bclk_div config missing or invalid\n");
		aif2_bclk_div = 12;
	} else {
		aif2_bclk_div = val;
		pr_debug("aif2_bclk_div=%d\n", val);
	}

	pr_debug("%s,line:%d\n", __func__, __LINE__);

	/* get and enable vcc-avcc */
	ac100->vol_supply.avcc = regulator_get(NULL, "vcc-avcc");
	if (IS_ERR(ac100->vol_supply.avcc)) {
		pr_err("get audio vcc-avcc failed\n");
		ret = -EFAULT;
	} else {
		ret = regulator_enable(ac100->vol_supply.avcc);
		if (ret) {
			pr_err("[%s]:vcc-avcc enable failed!\n", __func__);
			ret = EINVAL;
		}
	}

	/* get and enable vcc-io1 */
	ac100->vol_supply.io1 = regulator_get(NULL, "vcc-io1");
	if (IS_ERR(ac100->vol_supply.io1)) {
		pr_err("get audio vcc-io1 failed\n");
		ret = -EFAULT;
	} else {
		ret = regulator_enable(ac100->vol_supply.io1);
		if (ret) {
			pr_err("[%s]:vcc-io1 enable failed!\n", __func__);
			ret = EINVAL;
		}
	}

	/* get and enable vcc-io2 */
	ac100->vol_supply.io2 = regulator_get(NULL, "vcc-io2");
	if (IS_ERR(ac100->vol_supply.io2)) {
		pr_err("get audio vcc-io2 failed\n");
		ret = -EFAULT;
	} else {
		ret = regulator_enable(ac100->vol_supply.io2);
		if (ret) {
			pr_err("[%s]:vcc-io2 enable failed!\n", __func__);
			ret = EINVAL;
		}
	}

	/* get and enable vcc-ldoin */
	ac100->vol_supply.ldoin = regulator_get(NULL, "vcc-ldoin");
	if (IS_ERR(ac100->vol_supply.ldoin)) {
		pr_err("get audio vcc-ldoin failed\n");
		ret = -EFAULT;
	} else {
		ret = regulator_enable(ac100->vol_supply.ldoin);
		if (ret) {
			pr_err("[%s]:vcc-ldoin enable failed!\n", __func__);
			ret = EINVAL;
		}
	}

	/* get and enable vcc-cppvdd */
	ac100->vol_supply.cpvdd = regulator_get(NULL, "vcc-cpvdd");
	if (IS_ERR(ac100->vol_supply.cpvdd)) {
		pr_err("get audio vcc-cpvdd failed\n");
		ret = -EFAULT;
	} else {
		ret = regulator_enable(ac100->vol_supply.cpvdd);
		if (ret) {
			pr_err("[%s]:vcc-cpvdd enable failed!\n", __func__);
			ret = EINVAL;
		}
	}

	pr_err("%s : %d \n", __func__, __LINE__);
	set_configuration(ac100->codec);

	pr_err("%s : %d \n", __func__, __LINE__);
	/*enable this bit to prevent leakage from ldoin*/
	snd_soc_update_bits(codec, ADDA_TUNE3, (0x1<<OSCEN), (0x1<<OSCEN));
	snd_soc_write(codec, DAC_VOL_CTRL, 0);
	pr_err("%s : %d \n", __func__, __LINE__);
	ret = snd_soc_add_codec_controls(codec, ac100_controls,
		ARRAY_SIZE(ac100_controls));
	if (ret)
		pr_err("[AC100] Failed to register audio mode control\n");

	pr_err("%s : %d \n", __func__, __LINE__);
	snd_soc_dapm_new_controls(dapm, ac100_dapm_widgets,
		ARRAY_SIZE(ac100_dapm_widgets));
	snd_soc_dapm_add_routes(dapm, ac100_dapm_routes,
		ARRAY_SIZE(ac100_dapm_routes));

	return ret;
}

/* power down chip */
static int ac100_codec_remove(struct snd_soc_codec *codec)
{
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);
	int ret = 0;
#if 0
	devm_free_irq(codec->dev, ac100->jack_irq, NULL);
#endif
	ret = regulator_disable(ac100->vol_supply.avcc);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	regulator_put(ac100->vol_supply.avcc);

	ret = regulator_disable(ac100->vol_supply.io1);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	regulator_put(ac100->vol_supply.io1);

	ret = regulator_disable(ac100->vol_supply.io2);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	regulator_put(ac100->vol_supply.io2);

	ret = regulator_disable(ac100->vol_supply.ldoin);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	regulator_put(ac100->vol_supply.ldoin);

	ret = regulator_disable(ac100->vol_supply.cpvdd);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	regulator_put(ac100->vol_supply.cpvdd);

	kfree(ac100);
	return 0;
}

static int ac100_codec_suspend(struct snd_soc_codec *codec)
{
	int ret = 0;
	char pin_name[SUNXI_PIN_NAME_MAX_LEN];
	unsigned long config;
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	AC100_DBG("[codec]:suspend\n");
	/* check if called in talking standby */
/*
*	if (check_scene_locked(SCENE_TALKING_STANDBY) == 0) {
*		pr_err("In talking standby, audio codec do not suspend!!\n");
*		return 0;
*	}
*/
	ac100_set_bias_level(codec, SND_SOC_BIAS_OFF);

	ret = regulator_disable(ac100->vol_supply.avcc);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	ret = regulator_disable(ac100->vol_supply.io1);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	ret = regulator_disable(ac100->vol_supply.io2);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	ret = regulator_disable(ac100->vol_supply.ldoin);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);

	ret = regulator_disable(ac100->vol_supply.cpvdd);
	if (ret)
		pr_err("[AC100] %s(line:%d):fail to disable regulator!\n",
			__func__, __LINE__);
#if 0
	devm_free_irq(codec->dev, ac100->jack_irq, ac100);
	sunxi_gpio_to_name(ac100->jack_gpio, pin_name);
	config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_FUNC, 7);
	pin_config_set(SUNXI_PINCTRL, pin_name, config);
#endif
	if (spkgpio.used) {
		sunxi_gpio_to_name(spkgpio.gpio, pin_name);
		config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_FUNC, 7);
		pin_config_set(SUNXI_PINCTRL, pin_name, config);
	}

	return 0;
}

static int ac100_codec_resume(struct snd_soc_codec *codec)
{
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);

	AC100_DBG("[codec]:resume");

	ac100->switch_status = 0;

	ac100_set_bias_level(codec, SND_SOC_BIAS_STANDBY);
//	schedule_work(&ac100->codec_resume);
	return 0;
}

static unsigned int sndvir_audio_read(struct snd_soc_codec *codec,
	unsigned int reg)
{
	unsigned int data;
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);
	struct ac100 *ac100_dev = ac100->ac100;

	/* Device I/O API */
	data = ac100_reg_read(ac100_dev, reg);

	return data;
}

static int sndvir_audio_write(struct snd_soc_codec *codec,
	unsigned int reg, unsigned int value)
{
	int ret = 0;
	struct ac100_priv *ac100 = snd_soc_codec_get_drvdata(codec);
	struct ac100 *ac100_dev = ac100->ac100;

	ret = ac100_reg_write(ac100_dev, reg, value);

	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_sndvir_audio = {
	.probe = ac100_codec_probe,
	.remove = ac100_codec_remove,
	.suspend = ac100_codec_suspend,
	.resume = ac100_codec_resume,
	.set_bias_level = ac100_set_bias_level,
	.read = sndvir_audio_read,
	.write = sndvir_audio_write,
	.ignore_pmdown_time = 1,
};

static const struct of_device_id sunxi_codec_of_match[] = {
	{ .compatible = "allwinner,sunxi-ac100-codec", },
	{},
};

static int ac100_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct ac100_priv *ac100;
	struct gpio_config config;
	struct device_node *node = of_find_compatible_node(NULL, NULL, "allwinner,sunxi-ac100-codec");

	pr_err("%s,line:%d\n", __func__, __LINE__);

	if (!node) {
		dev_err(&pdev->dev, "can not get dt node for this device.\n");
		return -EINVAL;
	}
	ac100 = devm_kzalloc(&pdev->dev,
		sizeof(struct ac100_priv), GFP_KERNEL);
	if (ac100 == NULL)
		return -ENOMEM;

	platform_set_drvdata(pdev, ac100);

	ac100->ac100 = dev_get_drvdata(pdev->dev.parent);

	get_configuration(pdev);

	/*initial speaker gpio */
	spkgpio.gpio = of_get_named_gpio_flags(node, "gpio-spk", 0,
		(enum of_gpio_flags *)&config);
	if (!gpio_is_valid(spkgpio.gpio)) {
		pr_err("failed to get gpio-spk gpio from dts,spkgpio:%d\n",
			spkgpio.gpio);
		spkgpio.used = 0;
	} else {
		ret = devm_gpio_request(&pdev->dev, spkgpio.gpio, "SPK");
		if (ret) {
			spkgpio.used = 0;
			pr_err("failed to request gpio-spk gpio\n");
		} else {
			spkgpio.used = 1;
			gpio_direction_output(spkgpio.gpio, 1);
			gpio_set_value(spkgpio.gpio, 0);
			pr_debug("set spkgpio ok(spkgpio:%d)\n", spkgpio.gpio);
		}
	}

	/*initial headset irq gpio */
	ac100->jack_gpio = of_get_named_gpio_flags(node, "gpio-hs", 0,
		(enum of_gpio_flags *)&config);
	if (!gpio_is_valid(ac100->jack_gpio)) {
		pr_err("failed to get gpio-hs gpio from dts,hsgpio:%d\n",
			ac100->jack_gpio);
		ac100->hmic_used = 0;
	} else {
		ret = devm_gpio_request(&pdev->dev, ac100->jack_gpio,
					"HEADSET");
		if (ret) {
			ac100->hmic_used = 0;
			pr_err("failed to request gpio-hs gpio\n");
		} else {
			ac100->hmic_used = 1;
			pr_err("set headset gpio:%d\n", ac100->jack_gpio);
		}
	}

	ret = snd_soc_register_codec(&pdev->dev, &soc_codec_dev_sndvir_audio,
		ac100_dai, ARRAY_SIZE(ac100_dai));
	if (ret < 0)
		dev_err(&pdev->dev, "Failed to register ac100: %d\n", ret);

	ret = sysfs_create_group(&pdev->dev.kobj, &audio_debug_attr_group);
	if (ret)
		pr_err("failed to create attr group\n");

	return 0;
}

static void ac100_shutdown(struct platform_device *pdev)
{
	int reg_val;
	struct ac100_priv *ac100 = platform_get_drvdata(pdev);
	struct snd_soc_codec *codec = ac100->codec;

	/*set headphone volume to 0*/
	reg_val = snd_soc_read(codec, HPOUT_CTRL);
	reg_val &= ~(0x3f<<HP_VOL);
	snd_soc_write(codec, HPOUT_CTRL, reg_val);

	/*disable pa*/
	reg_val = snd_soc_read(codec, HPOUT_CTRL);
	reg_val &= ~(0x1<<HPPA_EN);
	snd_soc_write(codec, HPOUT_CTRL, reg_val);

	/*hardware xzh support*/
	reg_val = snd_soc_read(codec, OMIXER_DACA_CTRL);
	reg_val &= ~(0xf<<HPOUTPUTENABLE);
	snd_soc_write(codec, OMIXER_DACA_CTRL, reg_val);

	/*unmute l/r headphone pa*/
	reg_val = snd_soc_read(codec, HPOUT_CTRL);
	reg_val &= ~((0x1<<RHPPA_MUTE)|(0x1<<LHPPA_MUTE));
	snd_soc_write(codec, HPOUT_CTRL, reg_val);

	/*disable pa_ctrl*/
	if (spkgpio.used)
		gpio_set_value(spkgpio.gpio, 0);

//	snd_sunxi_unregister_jack(ac100);

}

static int ac100_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &audio_debug_attr_group);
	snd_soc_unregister_codec(&pdev->dev);
	return 0;
}

static struct platform_driver ac100_codec_driver = {
	.driver = {
		.name = "ac100-codec",
		.owner = THIS_MODULE,
	//	.of_match_table = sunxi_codec_of_match,
	},
	.probe = ac100_probe,
	.remove = ac100_remove,
	.shutdown = ac100_shutdown,
};
//module_platform_driver(ac100_codec_driver);

static int __init ac100_codec_driver_init(void)
{
	return platform_driver_register(&ac100_codec_driver);
}

static void __exit ac100_codec_driver_exit(void)
{
	platform_driver_unregister(&ac100_codec_driver);
}
late_initcall(ac100_codec_driver_init);
module_exit(ac100_codec_driver_exit);


MODULE_DESCRIPTION("ASoC AC100 driver");
MODULE_AUTHOR("huangxin");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ac100-codec");
