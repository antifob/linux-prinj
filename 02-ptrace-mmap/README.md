# Basic injection using ptrace - mmap allocation

The files in this directory demonstrates how to perform a simple
process injection using `ptrace`. Contrarily to the first example,
it shows how to allocate a new memory area in the target process
and use that to host the shellcode rather than touching the
existing address space.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to print `Hello World!\n`
  and return control transparently.

- `victim.c` is a simple program that prints it's pid and sleeps
  for a second, in a loop.

- `inject.c` contains the shellcode injection program. It takes the
  pid of the target process and the shellcode to inject.


## Example usage

```
# build everything
make

# in a terminal
./victim

# in another terminal
./inject ./hello $(pgrep victim)
```
