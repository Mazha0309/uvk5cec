#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

volatile uint16_t gHostHdlcCrc;
volatile uint8_t gHostAprsSetupFlag;
volatile uint8_t gHostBssPositionEnabled;
volatile uint8_t gHostRogerMode;
volatile int32_t gHostSubMenuSelection;
const char gHostFixedUInfoLabels[11][8] = {
    "MY CALL", "MY NAME", "MY GRID", "GPS LAT", "GPS LON", "DX CALL",
    "AprsDP1", "AprsDP2", "AprsMsg", "SSTV M1", "SSTV M2",
};
const char gHostRogerLabels[3][6] = {"OFF", "ROGER", "MDC"};

static const char *gUid;
static const char *gCall;
static const char *gLatitude;
static const char *gLongitude;
static uint8_t gSentValues[96];
static uint8_t gSentStuffing[96];
static uint8_t gSentCount;
static uint8_t gSetupCount;
static uint8_t gClockStartCount;
static uint8_t gStopCount;
static uint8_t gAudioPathOffCount;
static uint8_t gAudioPathEnabled;
static uint8_t gLifecycle;
static uint16_t gAfVolume;
static uint16_t gVolumeWrites[3];
static uint8_t gVolumeWriteCount;

uint8_t bss_build_frame(uint8_t *frame);
int bss_send_tail(void);
const char *roger_option_label(void);
void format_uinfo_label(char *output, uint8_t id);

void SETTINGS_FetchChannelName(char *output, int16_t id)
{
    const char *value = "";
    switch ((uint8_t)id) {
    case 0xAA: value = gCall; break;
    case 0xAD: value = gLatitude; break;
    case 0xAE: value = gLongitude; break;
    case 0xB5: value = gUid; break;
    default: break;
    }
    strncpy(output, value, 10);
    output[10] = '\0';
}

uint16_t BK4819_ReadRegister(uint8_t register_number)
{
    assert(register_number == 0x48);
    assert(gLifecycle == 0);
    return gAfVolume;
}

void BK4819_WriteRegister(uint8_t register_number, uint16_t value)
{
    assert(register_number == 0x48);
    assert(gVolumeWriteCount < 3);
    if (gVolumeWriteCount == 0)
        assert(gLifecycle == 0);
    else if (gVolumeWriteCount == 1)
        assert(gLifecycle == 1);
    else
        assert(gLifecycle == 3);
    gVolumeWrites[gVolumeWriteCount++] = value;
    gAfVolume = value;
}

void CEC_APRS_Setup(void)
{
    assert(gLifecycle == 0);
    assert(gHostAprsSetupFlag == 1);
    gLifecycle = 1;
    gAudioPathEnabled = 1;
    ++gSetupCount;
}

void CEC_AudioPathOff(void)
{
    if (gAudioPathOffCount == 0)
        assert(gLifecycle == 0);
    else if (gAudioPathOffCount == 1)
        assert(gLifecycle == 1);
    else
        assert(gLifecycle == 3);
    gAudioPathEnabled = 0;
    ++gAudioPathOffCount;
}

void CEC_APRS_ClockStart(uint8_t aprs_mode)
{
    assert(gLifecycle == 1);
    assert(gHostAprsSetupFlag == 0);
    assert(aprs_mode == 1);
    gLifecycle = 2;
    ++gClockStartCount;
}

void CEC_APRS_Stop(void)
{
    assert(gLifecycle == 2);
    gLifecycle = 3;
    ++gStopCount;
}

void CEC_HDLC_SendByte(uint8_t value, uint8_t stuffing)
{
    assert(gLifecycle == 2);
    assert(gSentCount < sizeof(gSentValues));
    gSentValues[gSentCount] = value;
    gSentStuffing[gSentCount++] = stuffing;

    uint16_t crc = gHostHdlcCrc;
    for (uint8_t bit = 0; bit < 8; ++bit) {
        const uint8_t input = (uint8_t)((value >> bit) & 1u);
        crc = (uint16_t)((crc >> 1) ^ (((crc ^ input) & 1u) ? 0x8408u : 0u));
    }
    gHostHdlcCrc = crc;
}

static void Configure(const char *position)
{
    gUid = "305419896";
    gCall = "N0CALL";
    gLatitude = "30.1234";
    gLongitude = "120.5678";
    gHostBssPositionEnabled = (uint8_t)(strcmp(position, "ON") == 0);
    gHostRogerMode = 3;
    gHostSubMenuSelection = 0;
    gSentCount = 0;
    gSetupCount = 0;
    gClockStartCount = 0;
    gStopCount = 0;
    gAudioPathOffCount = 0;
    gAudioPathEnabled = 1;
    gLifecycle = 0;
    gHostAprsSetupFlag = 0;
    gAfVolume = 0xB3A8;
    gVolumeWriteCount = 0;
}

static void TestFrameWithPosition(void)
{
    static const uint8_t expected[] = {
        0x01, 0x8B, 0x12, 0x34, 0x56, 0x78,
        0x07, 0x20, 'N', '0', 'C', 'A', 'L', 'L',
        0x0D, 0x25, 0x0D, 0xCA, 0x16, 0x37, 0x31, 0x0A,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
    };
    uint8_t frame[28];
    Configure("ON");
    assert(bss_build_frame(frame) == sizeof(expected));
    assert(memcmp(frame, expected, sizeof(expected)) == 0);
}

static void TestFrameWithoutPosition(void)
{
    uint8_t frame[28];
    Configure("OFF");
    assert(bss_build_frame(frame) == 14);
    assert(frame[6] == 0x07 && frame[7] == 0x20);
}

static void TestTailAndFcs(void)
{
    uint8_t frame[28];
    Configure("ON");
    const uint8_t length = bss_build_frame(frame);
    assert(bss_send_tail() == 1);
    assert(gSetupCount == 1);
    assert(gClockStartCount == 1);
    assert(gStopCount == 1);
    assert(gAudioPathOffCount == 3);
    assert(gAudioPathEnabled == 0);
    assert(gLifecycle == 3);
    assert(gVolumeWriteCount == 3);
    assert(gVolumeWrites[0] == 0xB000);
    assert(gVolumeWrites[1] == 0xB000);
    assert(gVolumeWrites[2] == 0xB3A8);
    assert(gAfVolume == 0xB3A8);
    assert(gSentCount == (uint8_t)(30 + length + 2 + 10));
    for (uint8_t i = 0; i < 30; ++i) {
        assert(gSentValues[i] == 0x7E);
        assert(gSentStuffing[i] == 0);
    }
    for (uint8_t i = 0; i < length; ++i) {
        assert(gSentValues[30 + i] == frame[i]);
        assert(gSentStuffing[30 + i] == 1);
    }
    assert(gSentValues[30 + length] == 0x26);
    assert(gSentValues[31 + length] == 0x55);
    assert(gSentStuffing[30 + length] == 1);
    assert(gSentStuffing[31 + length] == 1);
    for (uint8_t i = (uint8_t)(32 + length); i < gSentCount; ++i) {
        assert(gSentValues[i] == 0x7E);
        assert(gSentStuffing[i] == 0);
    }
}

static void TestDisabledUid(void)
{
    Configure("ON");
    gUid = "0";
    assert(bss_send_tail() == 0);
    assert(gSetupCount == 0 && gClockStartCount == 0 &&
           gStopCount == 0 && gSentCount == 0 && gLifecycle == 0 &&
           gAudioPathOffCount == 0 && gAudioPathEnabled == 1 &&
           gVolumeWriteCount == 0 && gAfVolume == 0xB3A8);
}

static void TestUidDoesNotEnableBss(void)
{
    Configure("ON");
    gHostRogerMode = 0;
    assert(bss_send_tail() == 0);
    assert(gSetupCount == 0 && gClockStartCount == 0 &&
           gStopCount == 0 && gSentCount == 0 && gLifecycle == 0 &&
           gAudioPathOffCount == 0 && gAudioPathEnabled == 1 &&
           gVolumeWriteCount == 0 && gAfVolume == 0xB3A8);
}

static void TestRogerLabels(void)
{
    static const char *const expected[] = {"OFF", "ROGER", "MDC", "BSS"};
    for (int32_t selection = 0; selection < 4; ++selection) {
        gHostSubMenuSelection = selection;
        assert(strcmp(roger_option_label(), expected[selection]) == 0);
    }
    gHostSubMenuSelection = 99;
    assert(strcmp(roger_option_label(), "OFF") == 0);
}

static void TestLabels(void)
{
    char label[16];
    format_uinfo_label(label, 0xB5);
    assert(strcmp(label, "BSS UID") == 0);
    format_uinfo_label(label, 0xB6);
    assert(strcmp(label, "CW MSG 1") == 0);
    format_uinfo_label(label, 0xAA);
    assert(strcmp(label, "MY CALL") == 0);
    format_uinfo_label(label, 0xB7);
    assert(strcmp(label, "CW MSG 2") == 0);
}

int main(void)
{
    TestFrameWithPosition();
    TestFrameWithoutPosition();
    TestTailAndFcs();
    TestDisabledUid();
    TestUidDoesNotEnableBss();
    TestRogerLabels();
    TestLabels();
    puts("BSS host tests: OK");
    return 0;
}
