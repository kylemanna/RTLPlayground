; SHA-256 sigma functions (FIPS 180-4, section 4.1.2).
; SDCC passes and returns the little-endian word in DPL, DPH, B, A.
	.module sha256_sigma
	.area BANK4 (CODE)

	.macro load_input
	mov	r3,a
	mov	r2,b
	mov	r1,dph
	mov	r0,dpl
	.endm

; The exchange chain rotates the bits through C and the bytes by one
; position at the same time. Each call rotates R0..R3 by nine bits.
right9:
	mov	a,r0
	rrc	a
	mov	a,r3
	rrc	a
	xch	a,r2
	rrc	a
	xch	a,r1
	rrc	a
	xch	a,r0
	rrc	a
	mov	r3,a
	ret
left9:
	mov	a,r3
	rlc	a
	mov	a,r0
	rlc	a
	xch	a,r1
	rlc	a
	xch	a,r2
	rlc	a
	xch	a,r3
	rlc	a
	mov	r0,a
	ret

; Accumulate each term into the return registers. R4 holds the high
; byte until the last term. Register selection accounts for byte rotates.
	.macro first x0,x1,x2,x3
	mov	dpl,x0
	mov	dph,x1
	mov	b,x2
	mov	a,x3
	mov	r4,a
	.endm
	.macro combine x0,x1,x2,x3
	mov	a,x0
	xrl	dpl,a
	mov	a,x1
	xrl	dph,a
	mov	a,x2
	xrl	b,a
	mov	a,x3
	xrl	a,r4
	.endm

_sha256_big0::
	load_input
	lcall	left9
	lcall	left9
	first	r1,r2,r3,r0	; ROTR22
	lcall	left9
	combine	r1,r2,r3,r0	; ROTR13
	mov	r4,a
	lcall	left9
	lcall	left9
	lcall	left9
	combine	r3,r0,r1,r2	; ROTR2
	ret

_sha256_big1::
	load_input
	lcall	right9
	first	r2,r3,r0,r1	; ROTR25
	lcall	right9
	lcall	right9
	combine	r2,r3,r0,r1	; ROTR11
	mov	r4,a
	lcall	right9
	lcall	right9
	lcall	right9
	combine	r2,r3,r0,r1	; ROTR6
	ret

; Rotate the original input right by seven directly into the result.
; The source registers remain available for ROTR18 and SHR3.
_sha256_small0::
	load_input
	mov	a,r0
	rlc	a
	mov	a,r1
	rlc	a
	mov	dpl,a
	mov	a,r2
	rlc	a
	mov	dph,a
	mov	a,r3
	rlc	a
	mov	b,a
	mov	a,r0
	rlc	a
	mov	r4,a
	lcall	right9
	lcall	right9
	combine	r0,r1,r2,r3	; ROTR18
	mov	r4,a
	lcall	right9
	mov	a,r1		; SHR3 = ROTR3 with three high bits cleared
	xrl	dpl,a
	mov	a,r2
	xrl	dph,a
	mov	a,r3
	xrl	b,a
	mov	a,r0
	anl	a,#0x1f
	xrl	a,r4
	ret

_sha256_small1::
	load_input
	lcall	right9
	first	r1,r2,r3,r0	; ROTR17
	lcall	right9
	mov	a,r3		; SHR10 contributes only 22 bits
	xrl	dpl,a
	mov	a,r0
	xrl	dph,a
	mov	a,r1
	anl	a,#0x3f
	xrl	b,a
	lcall	right9
	combine	r3,r0,r1,r2	; ROTR19
	ret
