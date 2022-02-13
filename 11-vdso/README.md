# Linux process injections - vDSO

This directory contains an example of code injections in the vDSO memory
segment. Essentially, it injects a small alternative to the `time`
vsyscall and a shellcode at the top of the segment. It then replaces
the beginning a function with a small shellcode that calls the shellcode
and then jumps to the small alternative (to prevent disrupting the host
process).
