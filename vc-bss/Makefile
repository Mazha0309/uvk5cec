BASE ?= ../../../Downloads/0.3v/cec_0.3VC.packed.bin
ARM_PREFIX ?= arm-none-eabi-

CC := $(ARM_PREFIX)gcc
LD := $(ARM_PREFIX)gcc
NM := $(ARM_PREFIX)nm
OBJCOPY := $(ARM_PREFIX)objcopy

BUILD := build
CFLAGS := -mcpu=cortex-m0 -mthumb -Os -std=c11 -ffreestanding \
	-ffunction-sections -fdata-sections -fno-builtin -fno-common \
	-fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables \
	-Wall -Wextra -Werror
LDFLAGS := -mcpu=cortex-m0 -mthumb -nostdlib -Wl,--gc-sections \
	-Wl,-Map,$(BUILD)/inject.map -T inject.ld

.PHONY: all clean test verify

all: $(BUILD)/cec_0.3VC-Mazha0309-BSS.packed.bin verify

$(BUILD):
	mkdir -p $@

$(BUILD)/bss_patch.o: bss_patch.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/hooks.o: hooks.S | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/inject.elf: $(BUILD)/hooks.o $(BUILD)/bss_patch.o inject.ld
	$(LD) $(LDFLAGS) $(BUILD)/hooks.o $(BUILD)/bss_patch.o -o $@

$(BUILD)/inject.bin: $(BUILD)/inject.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD)/inject.symbols: $(BUILD)/inject.elf
	$(NM) -n $< > $@

$(BUILD)/cec_0.3VC-Mazha0309-BSS.packed.bin: $(BUILD)/inject.bin $(BUILD)/inject.symbols patch_firmware.py
	python3 patch_firmware.py --base $(BASE) --inject $(BUILD)/inject.bin \
		--symbols $(BUILD)/inject.symbols --raw-output $(BUILD)/cec_0.3VC-Mazha0309-BSS.bin \
		--packed-output $@

test: | $(BUILD)
	cc -std=c11 -O2 -Wall -Wextra -Werror -DHOST_TEST \
		tests/test_bss.c bss_patch.c -o $(BUILD)/test_bss
	$(BUILD)/test_bss
	python3 -m unittest -v tests.test_patch tests.test_hdlc

verify: $(BUILD)/cec_0.3VC-Mazha0309-BSS.packed.bin test
	python3 verify_firmware.py --base $(BASE) \
		--raw $(BUILD)/cec_0.3VC-Mazha0309-BSS.bin \
		--packed $(BUILD)/cec_0.3VC-Mazha0309-BSS.packed.bin \
		--symbols $(BUILD)/inject.symbols

clean:
	rm -r $(BUILD)
