# Basic injection using ptrace - mmap allocation and clone

The files in this directory demonstrates how to perform a simple
process injection using `ptrace`. Contrarily to the first example,
it shows how to allocate a new memory area in the target process
and use that to host the shellcode rather than touching the existing
address space. Also, contrarily to the second example, the shellcode
uses `clone` to execute the payload in a thread in order to maintain
execution without disrupting the main thread.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a thread and run control transparently. The payload simply prints
  `Hello World!\n` in a loop.

- `victim.c` is a simple program that prints it's pid and sleeps
  for a second, in a loop.

- `ptrace.c` contains the shellcode injection program. It takes the
  pid of the target process and the shellcode to inject.


## Example usage

```
# build everything
make

# in a terminal
./victim

# in another terminal
./ptrace $(pgrep victim) ./hello
```
