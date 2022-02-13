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

import sys


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


def rdmap(pid, mp):
    with open('/proc/{}/mem'.format(pid), 'rb') as fp:
        fp.seek(mp['from'])
        return fp.read(mp['to'] - mp['from'])


if 2 != len(sys.argv):
    print('usage: dump-stack <pid>', file=sys.stderr)
    exit(1)


pid = sys.argv[1]

if sys.stdout.isatty():
    print('error: output is a terminal', file=sys.stderr)
    exit(1)

maps = getmaps(pid)
for m in maps:
    if '[stack]' == m['path']:
        sys.stdout.buffer.write(rdmap(pid, m))
