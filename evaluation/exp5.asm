imul r9d
not word ptr [r14 + r13]
adc dword ptr [r14 + r8], r12d
and byte ptr [r14 + r8], dl
not al
sar byte ptr [r14 + r8], cl
cmp rbx, 15
imul ax, word ptr [r14 + r10]
cmp ebx, dword ptr [r14 + r12]
movzx ax, r9b
setnz cl
setle dl
shr ebx, 53
sub edx, edx
sub dl, 100
pop rax
inc word ptr [r14 + r11]
sar rbx, 70
or word ptr [r14 + r13], 28
setnle cl
adc dl, 11
dec edx
and r13, 0xf
btr rax, r13
imul bl
shr word ptr [r14 + r13], 78
mul r8b
mul bx
and bx, 0xf
btc dx, bx
test cl, bl
not bx

