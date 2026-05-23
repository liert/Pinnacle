// Generic example: call imported malloc(16) and return the result in x0.
// Use with:
//   --strategy trampoline --mode raw --return-mode none

stp x29, x30, [sp, #-16]!
mov x29, sp

mov x0, #16
call_import malloc

ldp x29, x30, [sp], #16
ret
