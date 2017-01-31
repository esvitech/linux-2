#include "common.h"

#ifdef CONFIG_DWMAC_SUN8I
/*int sun8i_power_phy(struct net_device *ndev);
void sun8i_unpower_phy(struct stmmac_priv *priv);*/

struct mac_device_info *sun8i_dwmac_setup(void __iomem *ioaddr,
					  int *synopsys_id);
#else
struct mac_device_info *sun8i_dwmac_setup(void __iomem *ioaddr,
					  int *synopsys_id)
{
	return NULL;
}
#endif
