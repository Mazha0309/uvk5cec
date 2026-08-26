ENTRY(bss_tail_hook)

MEMORY
{
	CAVE (rx) : ORIGIN = 0x00003DC4, LENGTH = 0x774
}

/* Existing Thumb entry points in the official CEC 0.3VC image. */
CEC_APRS_ClockStart = 0x00000BC5;
CEC_AudioPathOff = 0x00000B51;
BK4819_ReadRegister = 0x00001179;
BK4819_WriteRegister = 0x000013C9;
CEC_HDLC_SendByte = 0x00001501;
CEC_APRS_Stop = 0x00001685;
CEC_APRS_Setup = 0x00001B61;
SETTINGS_FetchChannelName = 0x00007E9B;

SECTIONS
{
	.text ORIGIN(CAVE) :
	{
		KEEP(*(.text.bss_tail_hook))
		KEEP(*(.text.format_uinfo_label))
		KEEP(*(.text.roger_option_label))
		*(.text*)
		KEEP(*(.firmware_info))
		*(.rodata*)
		. = ALIGN(4);
		inject_end = .;
	} > CAVE

	/DISCARD/ :
	{
		*(.comment*)
		*(.ARM.attributes*)
		*(.eh_frame*)
		*(.note*)
	}
}

ASSERT(inject_end <= ORIGIN(CAVE) + LENGTH(CAVE), "BSS injection exceeds reclaimed DigiManager/FT8 area")
