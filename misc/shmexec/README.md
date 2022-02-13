# shm-based shellcode execution

The files in this directory demonstrates how to execute shellcode
using the SHM facility rather than the more common `mmap`.

- `hello.s` contains the shellcode that will be injected into the
  process. It coordinates with the loader to run the payload inside
  a thread and run control transparently. The payload simply prints
  `Hello World!\n` in a loop.

- `shmexec.c` contains the shellcode execution program. It takes the
  path to a shellcode to execute.


## Example usage

```
# build everything
make

# run PoC
./shmexec ./hello
```
