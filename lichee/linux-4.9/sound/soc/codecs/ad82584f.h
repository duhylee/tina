#ifndef _AD82584F_H
#define _AD82584F_H

#define MVOL                             0x03
#define C1VOL                            0x04
#define C2VOL                            0x05
#define CFADDR                           0x1d
#define A1CF1                            0x1e
#define A1CF2                            0x1f
#define A1CF3                            0x20
#define CFUD                             0x2d

#define AD82584F_REGISTER_COUNT		 0x86
#define AD82584F_RAM_TABLE_COUNT         0x80

struct ad82584f_platform_data {
	int reset_pin;
	int amp_en;
};

int ad82584f_set_volume_ext(int volume);
int ad82584f_get_volume_ext(void);

#endif
