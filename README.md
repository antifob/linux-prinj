# Linux process injection - PoCs

The source code in this repository accompanies the articles series at
https://blog.f0b.org/

I recommend to start working with the PoCs in a virtual machine without
any protections (Yama, SELinux, etc.) on. You can enable protections
(see part 3 of the series) to see their impact.

Do note, however, that pwntools, a tool used for most Python-based PoCs,
uses the Unicorn engine. This tool will *not* work with certain
protections on, but it *does not* mean that the technique(s) cannot be
used with those protections on.
