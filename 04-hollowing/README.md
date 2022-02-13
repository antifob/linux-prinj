# Process hollowing example

The files in this directory demonstrates how to perform a simple
process hollowing injection.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a thread and run control transparently. The payload simply prints
  `Hello World!\n` in a loop.

- `hollow.c` contains the shellcode injection program. It takes the
  path to a binary to inject into and the path to a shellcode to inject.


## Example usage

```
# build everything
make

# in another terminal
./hollow /bin/ls ./hello

ps a
```
