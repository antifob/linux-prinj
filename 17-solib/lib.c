/*
 * This file is part of the linux-prinj project.
 * https://gitlab.com/pgregoire/linux-prinj/
 *
 * Copyright 2022 Philippe Grégoire <git@pgregoire.xyz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>


__attribute__((constructor))
int foo(void)
{
	char b[4096];

	printf("hi from solib\n");
	snprintf(b, sizeof(b), "cat /proc/%i/maps", getpid());
	printf("%s\n", b);
	system(b);

	/* we won't get another opportunity to execute */
}
