.syntax unified
.cpu cortex-m0
.thumb

.section .text.bss_tail_hook, "ax", %progbits
.align 2
.global bss_tail_hook
.type bss_tail_hook, %function
.thumb_func
bss_tail_hook:
	/* This replaces the two instructions that load the existing Roger mode at
	 * the start of APP_EndTransmission. */
	/* Eight saved words keep SP 8-byte aligned across the C call. */
	push {r0, r1, r2, r4, r5, r6, r7, lr}
	bl bss_send_tail
	cmp r0, #0
	beq 1f

	/* A sent BSS frame is the complete tail.  Resume at the common radio
	 * cleanup and skip every old Roger/MDC/DTMF tail branch. */
	ldr r4, =0x20000094
	str r4, [sp, #12]
	ldr r6, [r4, #56]
	str r6, [sp, #20]
	mov r3, r6
	ldr r2, =0x00004D4F
	str r2, [sp, #28]
	b 2f
1:
	/* A non-BSS Roger mode, or a zero/empty UID: reproduce the two displaced
	 * instructions exactly and continue through the unmodified CEC tail logic. */
	adds r3, r5, #6
	ldrb r3, [r3, #31]
2:
	pop {r0, r1, r2, r4, r5, r6, r7, pc}
.size bss_tail_hook, . - bss_tail_hook
