#include <stdint.h>

enum {
	UINFO_MY_CALL = 0xAA,
	UINFO_GPS_LAT = 0xAD,
	UINFO_GPS_LON = 0xAE,
	UINFO_BSS_UID = 0xB5,
	UINFO_FIRST_CW_MESSAGE = 0xB6,
	UINFO_LAST = 0xBE,
	ROGER_MODE_BSS = 3,
	BSS_FRAME_MAX = 28,
	BK4819_REG_AF_VOLUME = 0x48,
	BK4819_AF_LEVEL_MASK = 0x0FFF,
};

extern void SETTINGS_FetchChannelName(char *output, int16_t id);
extern void CEC_AudioPathOff(void);
extern uint16_t BK4819_ReadRegister(uint8_t register_number);
extern void BK4819_WriteRegister(uint8_t register_number, uint16_t value);
extern void CEC_APRS_Setup(void);
extern void CEC_APRS_ClockStart(uint8_t aprs_mode);
extern void CEC_APRS_Stop(void);
extern void CEC_HDLC_SendByte(uint8_t value, uint8_t stuffing);

__attribute__((used, section(".firmware_info")))
const char FirmwareAttribution[] =
	"CEC 0.3VC BSS | Mazha0309 | assisted by GPT-5.6 Sol";

#ifdef HOST_TEST
extern volatile uint16_t gHostHdlcCrc;
extern volatile uint8_t gHostAprsSetupFlag;
extern volatile uint8_t gHostBssPositionEnabled;
extern volatile uint8_t gHostRogerMode;
extern volatile int32_t gHostSubMenuSelection;
extern const char gHostFixedUInfoLabels[11][8];
extern const char gHostRogerLabels[3][6];
#define HDLC_CRC gHostHdlcCrc
#define APRS_SETUP_FLAG gHostAprsSetupFlag
#define BSS_POSITION_ENABLED gHostBssPositionEnabled
#define ROGER_MODE gHostRogerMode
#define SUBMENU_SELECTION gHostSubMenuSelection
#define FIXED_UINFO_LABELS (&gHostFixedUInfoLabels[0][0])
#define ROGER_LABELS (&gHostRogerLabels[0][0])
#else
#define HDLC_CRC (*(volatile uint16_t *)0x20000004u)
#define APRS_SETUP_FLAG (*(volatile uint8_t *)0x200000D4u)
#define BSS_POSITION_ENABLED (*(volatile uint8_t *)0x20000149u)
#define ROGER_MODE (*(volatile uint8_t *)0x20000769u)
#define SUBMENU_SELECTION (*(volatile int32_t *)0x200000A0u)
#define FIXED_UINFO_LABELS ((const char *)0x0000DDBAu)
#define ROGER_LABELS ((const char *)0x0000DEE4u)
#endif

static uint8_t ascii_lower(uint8_t value)
{
	if (value >= 'A' && value <= 'Z')
		value = (uint8_t)(value + ('a' - 'A'));
	return value;
}

static uint8_t digit_value(uint8_t value)
{
	if (value >= '0' && value <= '9')
		return (uint8_t)(value - '0');
	value = ascii_lower(value);
	if (value >= 'a' && value <= 'f')
		return (uint8_t)(value - 'a' + 10);
	return 0xFF;
}

static uint32_t parse_uid(const char *text)
{
	uint32_t value = 0;
	uint8_t base = 10;
	uint8_t digits = 0;

	while (*text == ' ')
		++text;
	if (text[0] == '0' && ascii_lower((uint8_t)text[1]) == 'x') {
		base = 16;
		text += 2;
	}
	while (*text != '\0') {
		const uint8_t digit = digit_value((uint8_t)*text++);
		if (digit >= base)
			break;
		value = value * base + digit;
		++digits;
	}
	return digits == 0 ? 0 : value;
}

/* A compact, no-division coordinate parser.  Keeping the implementation
 * separate makes the arithmetic explicit and easy to host-test. */
static int32_t coordinate_raw(const char *text)
{
	static const uint16_t weights[4] = {3000, 300, 30, 3};
	uint32_t degrees = 0;
	uint32_t fraction = 0;
	uint8_t fraction_index = 0;
	uint8_t after_dot = 0;
	uint8_t negative = 0;

	while (*text == ' ')
		++text;
	if (ascii_lower((uint8_t)*text) == 's' || ascii_lower((uint8_t)*text) == 'w') {
		negative = 1;
		++text;
	} else if (ascii_lower((uint8_t)*text) == 'n' || ascii_lower((uint8_t)*text) == 'e') {
		++text;
	}
	if (*text == '-' || *text == '+') {
		negative = (uint8_t)(*text == '-');
		++text;
	}
	while (*text != '\0') {
		const uint8_t character = (uint8_t)*text++;
		if (character == '.') {
			after_dot = 1;
			continue;
		}
		if (character >= '0' && character <= '9') {
			const uint8_t digit = (uint8_t)(character - '0');
			if (!after_dot)
				degrees = degrees * 10u + digit;
			else if (fraction_index < 4)
				fraction += (uint32_t)digit * weights[fraction_index++];
			continue;
		}
		if (ascii_lower(character) == 's' || ascii_lower(character) == 'w')
			negative = 1;
	}
	const int32_t result = (int32_t)(degrees * 30000u + fraction);
	return negative ? -result : result;
}

static void put_u24_be(uint8_t **output, int32_t value)
{
	const uint32_t bits = (uint32_t)value;
	*(*output)++ = (uint8_t)(bits >> 16);
	*(*output)++ = (uint8_t)(bits >> 8);
	*(*output)++ = (uint8_t)bits;
}

uint8_t bss_build_frame(uint8_t *frame)
{
	char text[11];
	uint8_t *output = frame;

	SETTINGS_FetchChannelName(text, UINFO_BSS_UID);
	const uint32_t uid = parse_uid(text);
	if (uid == 0)
		return 0;

	*output++ = 0x01;
	*output++ = 0x8B;
	*output++ = (uint8_t)(uid >> 24);
	*output++ = (uint8_t)(uid >> 16);
	*output++ = (uint8_t)(uid >> 8);
	*output++ = (uint8_t)uid;

	SETTINGS_FetchChannelName(text, UINFO_MY_CALL);
	uint8_t call_length = 0;
	while (call_length < 6 && text[call_length] >= '!' &&
	       text[call_length] <= '~' && text[call_length] != '-')
		++call_length;
	if (call_length != 0) {
		*output++ = (uint8_t)(call_length + 1);
		*output++ = 0x20;
		for (uint8_t index = 0; index < call_length; ++index)
			*output++ = (uint8_t)text[index];
	}

	if (BSS_POSITION_ENABLED != 0) {
		*output++ = 0x0D;
		*output++ = 0x25;
		SETTINGS_FetchChannelName(text, UINFO_GPS_LAT);
		put_u24_be(&output, coordinate_raw(text));
		SETTINGS_FetchChannelName(text, UINFO_GPS_LON);
		put_u24_be(&output, coordinate_raw(text));
		*output++ = 0;
		*output++ = 0;       /* altitude unavailable */
		*output++ = 0;
		*output++ = 0;       /* speed unavailable */
		*output++ = 0xFF;
		*output++ = 0xFF;    /* heading unknown */
	}

	return (uint8_t)(output - frame);
}

int bss_send_tail(void)
{
	/* A populated UID is data, not an enable switch.  BSS transmission is
	 * selected explicitly as the fourth Roger mode. */
	if (ROGER_MODE != ROGER_MODE_BSS)
		return 0;

	uint8_t frame[BSS_FRAME_MAX];
	const uint8_t length = bss_build_frame(frame);
	if (length == 0)
		return 0;

	const uint16_t normal_af_volume =
		BK4819_ReadRegister(BK4819_REG_AF_VOLUME);
	/* REG 0x48 Gain-2 value zero is the BK4819 AF-output mute.  Clear all
	 * three AF gain stages while preserving the unrelated upper nibble. */
	const uint16_t muted_af_volume = (uint16_t)(
		normal_af_volume & (uint16_t)~BK4819_AF_LEVEL_MASK);
	/* REG 0x48 alone does not silence CEC's APRS monitor: CEC_APRS_Setup also
	 * enables the external speaker amplifier through GPIOC AUDIO_PATH.  Keep
	 * both mute layers off before setup, immediately after setup re-enables the
	 * amplifier, and once more after shutdown.  The caller's normal post-TX
	 * cleanup owns the next legitimate speaker enable. */
	CEC_AudioPathOff();
	BK4819_WriteRegister(BK4819_REG_AF_VOLUME, muted_af_volume);
	/* Mirror CEC's native APRS wrapper exactly around radio setup. */
	APRS_SETUP_FLAG = 1;
	CEC_APRS_Setup();
	APRS_SETUP_FLAG = 0;
	CEC_AudioPathOff();
	BK4819_WriteRegister(BK4819_REG_AF_VOLUME, muted_af_volume);
	/* HDLC_SendByte waits on the timer flag driven by this native CEC clock.
	 * Without it, transmission remains forever on the setup's initial tone. */
	CEC_APRS_ClockStart(1);
	for (uint8_t count = 0; count < 30; ++count)
		CEC_HDLC_SendByte(0x7E, 0);

	HDLC_CRC = 0xFFFF;
	for (uint8_t index = 0; index < length; ++index)
		CEC_HDLC_SendByte(frame[index], 1);
	const uint16_t fcs = (uint16_t)~HDLC_CRC;
	CEC_HDLC_SendByte((uint8_t)fcs, 1);
	CEC_HDLC_SendByte((uint8_t)(fcs >> 8), 1);

	for (uint8_t count = 0; count < 10; ++count)
		CEC_HDLC_SendByte(0x7E, 0);

	/* CEC_APRS_Setup keys the radio and changes the BK4819 signal path.  It
	 * must be paired with the same full shutdown used by CEC's native APRS
	 * sender; the ordinary Roger/DTMF cleanup alone does not release it. */
	CEC_APRS_Stop();
	CEC_AudioPathOff();
	BK4819_WriteRegister(BK4819_REG_AF_VOLUME, normal_af_volume);
	return 1;
}

__attribute__((used, section(".text.roger_option_label")))
const char *roger_option_label(void)
{
	const int32_t selection = SUBMENU_SELECTION;
	if (selection == ROGER_MODE_BSS)
		return "BSS";
	if ((uint32_t)selection < ROGER_MODE_BSS)
		return ROGER_LABELS + (uint32_t)selection * 6u;
	return ROGER_LABELS;
}

static void copy_label(char *output, const char *source)
{
	do {
		*output = *source++;
	} while (*output++ != '\0');
}

void format_uinfo_label(char *output, uint8_t id)
{
	if (id == UINFO_BSS_UID) {
		copy_label(output, "BSS UID");
		return;
	}
	if (id >= 0xAA && id <= 0xB4) {
		copy_label(output, FIXED_UINFO_LABELS + (uint8_t)(id - 0xAA) * 8u);
		return;
	}
	if (id >= UINFO_FIRST_CW_MESSAGE && id <= UINFO_LAST) {
		copy_label(output, "CW MSG ");
		output[7] = (char)('0' + id - UINFO_BSS_UID);
		output[8] = '\0';
		return;
	}
	*output = '\0';
}
