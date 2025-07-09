mov al, bl  # load secret byte
test al, 1               
jz skip
# Secret dependent path
or rcx, 1
and rdx, rcx
shr rdx, 1
div rcx
skip:
# Secret independent path
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111
and rax, 0b11111111