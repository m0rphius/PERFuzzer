# Assume:
# r14 = base address of scratch memory
# r8  = secret index (e.g., between 0 and 255)

# Flush the address [r14 + r8] from cache for clean results
clflush byte ptr [r14 + r8]

# Access some memory at offset = r9
mov     al, byte ptr [r14 + r9]

# Access memory at a secret-dependent offset
mov     dl, byte ptr [r14 + r8]   # <- violation here!