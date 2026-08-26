# CEC 0.3VC — Mazha0309 BSS patch

This directory contains a reproducible binary patch for the official
`cec_0.3VC.packed.bin`.  The later CEC source was never published, so the patch
is linked into the space reclaimed from its DigiManager/FT8 subsystem.

Changes:

- keeps `MySSID`, standalone `T.APRS`, SSTV and spectrum behavior unchanged;
- removes the `DIG.M` and `T.WSPR` menu entries and disables their three entry
  calls;
- adds a Vero-compatible BSS AFSK/HDLC tail after PTT release, using CEC's
  complete native APRS setup, 1200-baud clock and radio shutdown sequence; when
  enabled it replaces the old Roger/MDC/DTMF tail rather than being mixed with
  it;
- adds `BSS` as the fourth `Roger` choice; a populated UID alone never enables
  transmission;
- uses `U.Info` `B5` only as `BSS UID` and restores `B6` as `CW MSG 1`;
- replaces the unused external-key `CW KEY` menu with a persistent `BSSPOS`
  `OFF`/`ON` switch, while disabling the old key-runtime branches;
- uses the existing `MY CALL`, `GPS LAT` and `GPS LON` fields without modifying
  their storage;
- changes `POnMsg` -> `MESSAGE` to show `U.Info` `MY CALL` on the first line
  and `MY NAME` on the second, instead of the unrelated legacy welcome slots;
- mutes both the BK4819 AF gain and the independent GPIOC speaker-amplifier
  path throughout the BSS tail, without changing the transmitted AFSK level;
- identifies both the raw firmware and packed update image as `Mazha0309`.

`BSS UID` accepts decimal or `0x` hexadecimal.  Select `Roger` -> `BSS` to
enable the tail; selecting `OFF`, `ROGER`, or `MDC` keeps their original
behavior regardless of whether a UID is filled in.  Set the standalone
`BSSPOS` menu to `ON` to include `GPS LAT` and `GPS LON`, or `OFF` to send
identity/callsign only.  An empty/zero UID prevents a BSS frame even while the
Roger mode is `BSS`.

Build with the ARM GNU 10.3.1 toolchain used by CEC:

```sh
make ARM_PREFIX=/path/to/gcc-arm-none-eabi-10.3/bin/arm-none-eabi-
```

The patcher refuses any base image whose SHA-256 differs from the official
0.3VC asset.  `make verify` also checks that code changes remain inside the
declared hook/cave/menu/version ranges.  Flashing firmware remains an at-your-
own-risk operation; back up EEPROM/calibration data first.

CEC is by KD8CEC/phdlee and derives from the open UV-K5 firmware community.
This BSS adaptation is authored for Mazha0309; implementation assistance was
provided by GPT-5.6 Sol.
