#ifndef _ES7243_H
#define _ES7243_H




#define ES7243_REGISTER_COUNT 0xff
#if 0
struct reg_default ad82584f_reg_defaults[ES7243_REGISTER_COUNT] = {
//	{0x02, 0x7f},								//mute
	{0x03, 0x18},                               //Master Vol default=-110dB(mute}
	{0x04, 0x13};                               //CH1 Vol default=2.5dB
	{0x05, 0x13};                               //CH2 Vol default=2.5dB
//	{0x0a, 0x10};								//Bass_tone_control 12dB~-12dB 360Hz 0dB
//	{0x0b, 0x15};								//Treble_tone_control 12dB~-12dB 7KHz -5dB
//	{0x09, 0x02};								//Bass_management_crossover_frequency 0x01=120Hz
	{0x0c, 0x98};								//State_Control_4(surround_off+Bass_treble_off+EQ_CH1toCH2}
    {0x0d, 0x12};								//CH1 DRC & Power clipping enable RMS mode+HPF-off
    {0x0e, 0x12};								//CH2 DRC & Power clipping enable RMS mode+HPF-off
	{0x1a, 0x32};								//State_Control_5(reset_off+MCLK_on+power_saving_off+2.0CH_mode}
	{0x1b, 0x81};								//PVDD_UVP default=0x81=off+7.2V	0x01=on+7.2
};
#endif
#endif
