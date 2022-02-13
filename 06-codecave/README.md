# Code cave

The files in this directory demonstrates an injection technique
targeting code caves of the process's program.

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
