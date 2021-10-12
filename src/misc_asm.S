#
# Copyright IBM Corp. 2021
#
# libzpc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

.text

# void memzero_secure(void *buf, size_t buflen)
.globl	memzero_secure
.type	memzero_secure,@function
.align	16
memzero_secure:
.cfi_startproc
	ltgr	%r3,%r3
	ber	%r14
	aghi	%r3,-1
	srlg	%r1,%r3,8
	ltgr	%r1,%r1
	je	.Lmemzero_secure_skip
.Lmemzero_secure_oop:
	xc	0(256,%r2),0(%r2)
	la	%r2,256(%r2)
	brctg	%r1,.Lmemzero_secure_oop
.Lmemzero_secure_skip:
	larl	%r1,.Lmemzero_secure_xc
	ex	%r3,0(%r1)
	br	%r14
.Lmemzero_secure_xc:
	xc	0(1,%r2),0(%r2)
.cfi_endproc
.size	memzero_secure, .-memzero_secure

# int memcmp_consttime(const void *buf1, const void *buf2, size_t buflen)
.globl  memcmp_consttime
.type   memcmp_consttime,@function
.align  16
memcmp_consttime:
.cfi_startproc
        lghi    %r5,0
        clgr    %r4,%r5
        je      .Lmemcmp_consttime_skip
.Lmemcmp_consttime_loop:
        llgc    %r0,0(%r2)
        la      %r2,1(%r2)
        llgc    %r1,0(%r3)
        la      %r3,1(%r3)
        xr      %r1,%r0
        or      %r5,%r1
        brctg   %r4,.Lmemcmp_consttime_loop

        lnr     %r5,%r5
        srl     %r5,31
.Lmemcmp_consttime_skip:
        lgr     %r2,%r5
        br      %r14
.cfi_endproc
.size	memcmp_consttime, .-memcmp_consttime
.size   memcmp_consttime,.-memcmp_consttime
