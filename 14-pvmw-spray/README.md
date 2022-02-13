# process_vm_writev spray

The files in this directory demonstrates an injection technique
using process_vm_writev. It entirely uses the stack for the
shellcode and execution redirection. It:

- uses the target's libc to find gadgets and build a ROP chain
  that sets the stack executable;
- uses the target's libc to find gadgets and build a stack
  pivot ROP chain (`pop rsp; ret`);
- writes the first ROP chain and shellcode at the bottom of the
  stack memory area and sprays the remainder of the stack with
  the stack pivot gadget.

This is not a reliable technique and relies entirely on the fact
that (1) the target (`victim`) sleeps for 1 second (therefore
not using the stack while we inject into it) and (2) our stack
spraying aligns well with the return's address location.
tl;dr: Will not work sometimes and might need adjustment depending
on the build.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a thread and run control transparently. The payload simply prints
  `Hello World!\n` in a loop.

- `victim.c` is a simple program that prints it's pid and sleeps
  for a second, in a loop.

- `inject.py` contains the shellcode injection program. It takes the
  shellcode to inject and, optionally, the target process's pid as its
  arguments. If no pid is given, an arbitrary process is injected into.


## Example usage

```
# build everything
make

# run victim program
./victim

# in another terminal
python3 inject.py ./hello $(pgrep victim)
```
