/*
 * Copyright(c) 2018-2021 Allwinnertech Co., Ltd.
 *
 * Author: frank <frank@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */
#include <linux/clk.h>
#include <linux/devfreq.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/sunxi_dramfreq.h>

#include "sunxi-mdfs.h"

static int sunxi_dramfreq_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct sunxi_dramfreq *dramfreq = dev_get_drvdata(dev);
	unsigned long pll_ddr_rate;
	unsigned int dram_div_m;

	pll_ddr_rate = clk_get_rate(dramfreq->clk_pll_ddr0) / 1000;

	dram_div_m = (readl(dramfreq->ccu_base + _DRAM_CLK_REG) & 0x3) + 1;
	*freq = pll_ddr_rate / 2 / dram_div_m;

	return 0;
}

static int sunxi_dramfreq_target(struct device *dev,
						unsigned long *freq, u32 flags)
{
	struct sunxi_dramfreq *dramfreq = dev_get_drvdata(dev);
	unsigned long old_rate, target_rate;
	struct dev_pm_opp *opp;
	int rc = 0;

	rcu_read_lock();
	opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(opp)) {
		rcu_read_unlock();
		return PTR_ERR(opp);
	}

	target_rate = dev_pm_opp_get_freq(opp);
	old_rate = dev_pm_opp_get_freq(dramfreq->curr_opp);
	rcu_read_unlock();

	if (old_rate == target_rate)
		return 0;

	/* start frequency scaling */
	mutex_lock(&dramfreq->lock);

	dev_info(dev, "%luHz->%luHz start\n",
				old_rate, target_rate);

	if (dramfreq->mode == DFS_MODE)
		rc = mdfs_dfs(dramfreq, target_rate / 1000 / 1000);
	if (rc)
		goto out;

	dev_info(dev, "over\n");

	dramfreq->curr_opp = opp;

out:
	mutex_unlock(&dramfreq->lock);
	return rc;
}

static int sunxi_get_dev_status(struct device *dev,
				struct devfreq_dev_status *stat)
{
	return 0;
}

static struct devfreq_dev_profile sunxi_dramfreq_profile = {
	.polling_ms     = 200,
	.get_cur_freq   = sunxi_dramfreq_get_cur_freq,
	.target         = sunxi_dramfreq_target,
	.get_dev_status = sunxi_get_dev_status,
};

static int sunxi_dramfreq_paras_init(struct sunxi_dramfreq *dramfreq)
{
	struct device_node *dram_np;
	int rc = 0;

	dram_np = of_find_node_by_path("/dram");
	if (!dram_np)
		return -ENODEV;

	rc = of_property_read_u32(dram_np, "dram_clk",
					&dramfreq->dram_para.dram_clk);
	rc |= of_property_read_u32(dram_np, "dram_type",
					&dramfreq->dram_para.dram_type);
	rc |= of_property_read_u32(dram_np, "dram_odt_en",
					&dramfreq->dram_para.dram_odt_en);
	rc |= of_property_read_u32(dram_np, "dram_tpr9",
					&dramfreq->dram_para.dram_tpr9);
	rc |= of_property_read_u32(dram_np, "dram_tpr13",
					&dramfreq->dram_para.dram_tpr13);
	if (rc)
		goto out_put_node;

	/* use dramfreq or not */
	if (!((dramfreq->dram_para.dram_tpr13 >> 11) & 0x1)) {
		rc = -EINVAL;
		goto out_put_node;
	}

	dramfreq->mode = (dramfreq->dram_para.dram_tpr13 >> 10) & 0x1;

out_put_node:
	of_node_put(dram_np);
	return rc;
}

static int sunxi_dramfreq_resource_init(struct platform_device *pdev,
					struct sunxi_dramfreq *dramfreq)
{
	dramfreq->dramcom_base = of_iomap(pdev->dev.of_node, 0);
	if (!dramfreq->dramcom_base)
		return PTR_ERR(dramfreq->dramcom_base);

	dramfreq->dramctl_base = of_iomap(pdev->dev.of_node, 1);
	if (!dramfreq->dramctl_base)
		return PTR_ERR(dramfreq->dramctl_base);

	dramfreq->ccu_base = of_iomap(pdev->dev.of_node, 2);
	if (!dramfreq->ccu_base)
		return PTR_ERR(dramfreq->ccu_base);

	dramfreq->clk_pll_ddr0 = of_clk_get(pdev->dev.of_node, 0);
	if (IS_ERR(dramfreq->clk_pll_ddr0))
		return PTR_ERR(dramfreq->clk_pll_ddr0);

	return 0;
}

static void sunxi_dramfreq_hw_init(struct sunxi_dramfreq *dramfreq)
{
	volatile unsigned int reg_val;

	if (dramfreq->mode == DFS_MODE) {
		writel(0xFFFFFFFF, dramfreq->dramcom_base + MC_MDFSMRMR);

		/* set DFS time */
		reg_val = readl(dramfreq->dramctl_base + PTR2);
		reg_val &= ~0x7fff;
		reg_val |= (0x7<<10 | 0x7<<5 | 0x7<<0);
		writel(reg_val, dramfreq->dramctl_base + PTR2);
	}
}

static int sunxi_dramfreq_probe(struct platform_device *pdev)
{
	struct sunxi_dramfreq *dramfreq;
	struct devfreq_simple_ondemand_data *ondemand_data;
	struct device *dev = &pdev->dev;
	unsigned long rate;
	int rc = 0;

	dramfreq = devm_kzalloc(dev, sizeof(*dramfreq), GFP_KERNEL);
	if (!dramfreq)
		return -ENOMEM;

	rc = sunxi_dramfreq_paras_init(dramfreq);
	if (rc)
		goto err;

	rc = sunxi_dramfreq_resource_init(pdev, dramfreq);
	if (rc)
		goto err;

	/*
	 * We add a devfreq driver to our parent since it has a device tree node
	 * with operating points.
	 */
	rcu_read_lock();
	if (dev_pm_opp_of_add_table(dev)) {
		dev_err(dev, "Invalid operating-points in device tree.\n");
		rcu_read_unlock();
		return -EINVAL;
	}

	rate = clk_get_rate(dramfreq->clk_pll_ddr0);
	dramfreq->curr_opp = devfreq_recommended_opp(dev, &rate,
					DEVFREQ_FLAG_LEAST_UPPER_BOUND);
	if (IS_ERR(dramfreq->curr_opp)) {
		dev_err(dev, "failed to find dev_pm_opp\n");
		rcu_read_unlock();
		rc = PTR_ERR(dramfreq->curr_opp);
		goto err;
	}
	rcu_read_unlock();

	ondemand_data = devm_kzalloc(dev, sizeof(*ondemand_data), GFP_KERNEL);
	if (!ondemand_data) {
		rc = -ENOMEM;
		goto err;
	}
	ondemand_data->upthreshold = 40;
	ondemand_data->downdifferential = 5;

	/* Add devfreq device to monitor */
	dramfreq->devfreq = devm_devfreq_add_device(dev,
					&sunxi_dramfreq_profile,
					"simple_ondemand", ondemand_data);
	if (IS_ERR(dramfreq->devfreq)) {
		dev_err(dev, "failed to add devfreq device\n");
		rc = PTR_ERR(dramfreq->devfreq);
		goto err;
	}

	platform_set_drvdata(pdev, dramfreq);

	mutex_init(&dramfreq->lock);

	/* init some hardware paras*/
	sunxi_dramfreq_hw_init(dramfreq);

	return 0;

err:
	dev_pm_opp_of_remove_table(dev);
	return rc;
}

static const struct of_device_id sunxi_dramfreq_match[] = {
	{ .compatible = "allwinner,sunxi-dramfreq", },
	{},
};

static struct platform_driver sunxi_dramfreq_driver = {
	.probe  = sunxi_dramfreq_probe,
	.driver = {
		.name  = "sunxi-dramfreq",
		.owner = THIS_MODULE,
		.of_match_table = sunxi_dramfreq_match,
	},
};
module_platform_driver(sunxi_dramfreq_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank <frank@allwinnertech.com>");
MODULE_DESCRIPTION("SUNXI dramfreq driver");
