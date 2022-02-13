# Linux process injections - GOT hooking

This directory contains an example of code injections using GOT hooking.
It injects a payload in memory and replaces a GOT entry that will be
executed in place of the original routine. The original routine's
address is placed just in front of the payload so it can return to it.
