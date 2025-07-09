# Compare a_len (ecx) and b_len (edx)
cmp     ecx, edx
jne     not_equal_lengths

# rsi = r14 + r9 = base address of a[]
lea     r11, [r14 + r9]
# rdi = r14 + r10 = base address of b[]
lea     r12, [r14 + r10]

xor     rax, rax          # rax = 0 (will hold return value false by default)
xor     r8d, r8d          # r8d = i = 0

compare_loop:
cmp     r8d, ecx          # i < a_len?
jge     arrays_equal      # if i >= a_len, done: arrays are equal

# Load byte from a[i] and b[i]
mov     al, byte ptr [r11 + r8]
mov     dl, byte ptr [r12 + r8]
cmp     al, dl
jne     not_equal_bytes

inc     r8d
jmp     compare_loop

arrays_equal:
mov     al, 1             # return true
jmp     done

not_equal_lengths:
not_equal_bytes:
xor     al, al            # return false

done:

