; One BLAKE2s/BLAKE3 round. R0..R3 hold byte offsets for A..D;
; R4..R7 hold one little-endian working word. Use full XRAM addresses:
; neither the state nor the message must be aligned to a 256-byte page.
	.globl _blake_state, _blake_block, _blake_lanes, _blake_skip_high_words
	.area BANK4 (CODE)

	.macro word_address base
	add	a,#<base
	mov	dpl,a
	clr	a
	addc	a,#>base
	mov	dph,a
	.endm

	.macro load_byte reg
	movx	a,@dptr
	mov	reg,a
	.endm
	.macro store_byte reg
	mov	a,reg
	movx	@dptr,a
	.endm
	.macro add_byte op,reg
	movx	a,@dptr
	op	a,reg
	mov	reg,a
	.endm
	.macro xor_byte reg
	movx	a,@dptr
	xrl	a,reg
	mov	reg,a
	.endm

; Expand or call the same word operations to isolate the cost of call/return.
	.macro four_bytes op
	op	r4
	inc	dptr
	op	r5
	inc	dptr
	op	r6
	inc	dptr
	op	r7
	.endm

	.macro accumulate op,reg
	movx	a,@dptr
	op	a,reg
	movx	@dptr,a
	mov	reg,a
	.endm

	.macro four_adds op
	op	add,r4
	inc	dptr
	op	addc,r5
	inc	dptr
	op	addc,r6
	inc	dptr
	op	addc,r7
	.endm

	.macro load_state
	word_address _blake_state
	four_bytes load_byte
	.endm
	.macro store_state
	word_address _blake_state
	four_bytes store_byte
	.endm
	.macro add_word
	four_adds add_byte
	.endm
	.macro add_state
	word_address _blake_state
	add_word
	.endm
	.macro xor_state
	word_address _blake_state
	four_bytes xor_byte
	.endm
	.macro add_store_state
	word_address _blake_state
	four_adds accumulate
	.endm

	.macro apply op,target
	.if INLINE_WORDS
	op
	.else
	lcall	target
	.endif
	.endm

	.ifne 1-INLINE_WORDS
load_fn:
	load_state
	ret
store_fn:
	store_state
	ret
add_state_fn:
	word_address _blake_state
add_fn:
	add_word
	ret
xor_fn:
	xor_state
	ret
; Accumulate D into C in one pass and keep C for the following XOR.
accumulate_fn:
	add_store_state
	ret
	.endif

; A += B + message; working word = D ^ A. B holds the message index.
	.macro first_pair ?add_msg,?save_a
	mov	a,r0
	apply	load_state,load_fn
	mov	a,r1
	apply	add_state,add_state_fn
	mov	a,b
	jnb	_blake_skip_high_words,add_msg
	jb	acc.3,save_a
add_msg:
	rl	a
	rl	a
	word_address _blake_block
	apply	add_word,add_fn
save_a:
	mov	a,r0
	apply	store_state,store_fn
	mov	a,r3
	apply	xor_state,xor_fn
	.endm

; D is already rotated. C += D; working word = B ^ C.
	.macro second_pair
	mov	a,r3
	apply	store_state,store_fn
	mov	a,r2
	apply	add_store_state,accumulate_fn
	mov	a,r1
	apply	xor_state,xor_fn
	mov	a,r1
	word_address _blake_state
	.endm

	.macro lane reg,offset
	mov	a,b
	add	a,#offset
	movc	a,@a+dptr
	rl	a
	rl	a
	mov	reg,a
	.endm

	.macro nibble_pair lo,hi
; Keep the high nibble of lo and substitute the low nibble of hi.
	mov	a,lo
	xrl	a,hi
	anl	a,#0x0f
	xrl	a,lo
	swap	a
	movx	@dptr,a
	.endm

	.macro shift_store reg
	mov	a,reg
	rlc	a
	movx	@dptr,a
	.endm

	.if INLINE_WORDS
_blake_inline_round::
	.else
_blake_asm_round::
	.endif
	mov	b,#0
group:
	; Keep the next schedule pointer, group offset and packed message
	; pair across the two halves of G. No persistent scratch allocation.
	clr	a
	movc	a,@a+dptr
	inc	dptr
	push	dpl
	push	dph
	push	b
	push	acc
	swap	a
	anl	a,#0x0f
	mov	r4,a
	mov	dptr,#_blake_lanes
	lane	r0,0
	lane	r1,1
	lane	r2,2
	lane	r3,3
	mov	b,r4
	first_pair
	; ROTR16 exchanges the two pairs of bytes.
	mov	a,r4
	xch	a,r6
	mov	r4,a
	mov	a,r5
	xch	a,r7
	mov	r5,a
	second_pair
	; ROTR12 writes adjacent nibbles in byte-rotated order.
	nibble_pair r5,r6
	inc	dptr
	nibble_pair r6,r7
	inc	dptr
	nibble_pair r7,r4
	inc	dptr
	nibble_pair r4,r5

	pop	acc
	anl	a,#0x0f
	mov	b,a
	first_pair
	; ROTR8 maps bytes 0,1,2,3 to 1,2,3,0.
	mov	a,r4
	xch	a,r7
	xch	a,r6
	xch	a,r5
	mov	r4,a
	second_pair
	; ROTR7 = ROTL1 followed by ROTR8. Seed from byte 0 and stream
	; the rotated bytes in final order. MOVX and INC DPTR preserve carry.
	mov	a,r4
	rlc	a
	shift_store r5
	inc	dptr
	shift_store r6
	inc	dptr
	shift_store r7
	inc	dptr
	shift_store r4
	pop	b
	pop	dph
	pop	dpl
	mov	a,b
	add	a,#4
	mov	b,a
	cjne	a,#32,next_group
	ret
next_group:
	ljmp	group
