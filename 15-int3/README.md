# Linux process injection - ptrace+mmap+fork+int3

The files in this directory demonstrates how to perform a simple
process injection using `ptrace`. It allocate a new memory area in
the target process using `mmap` and copy the shellcode in it. It then
runs the shellcode which calls `fork` to execute the shellcode.
Synchronization between the loader and payload is done using `int 3`.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a thread and run control transparently. The payload simply prints
  `Hello World!\n` in a loop.

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

# observe the child process
ps | grep victim
```
