# Parallel execution using clone

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a child process and run transparently. The payload simply prints
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

# observe the thread
ps -eLF | grep victim
```
