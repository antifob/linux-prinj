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

#define _XOPEN_SOURCE 700

#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <time.h>


static void handler1(int _)
{
	/* avoid compiler warnings */
	(void)_;

	puts("handler 1");
}

static void handler2(union sigval _)
{
	/* avoid compiler warnings */
	(void)_;

	puts("handler 2");
}


int main(void)
{
	int tmr1;
	timer_t tmr2;
	struct sigevent sev;
	struct itimerval itv;


	if (0 > signal(SIGALRM, handler1)) {
		perror("signal");
		return 1;
	}

	memset(&itv, 0, sizeof(itv));
	itv.it_value.tv_sec  = 3600;
	itv.it_value.tv_usec = 0;
	printf("Setting up timer with signal %i\n", SIGALRM);
	if (0 > (tmr1 = setitimer(ITIMER_REAL,  &itv, 0))) {
		perror("setitimer");
		return 1;
	}

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo  = SIGRTMIN;

	printf("Setting up timer with signal SIGRTMIN/%i\n", SIGRTMIN);
	if (0 > timer_create(CLOCK_MONOTONIC, &sev, &tmr2)) {
		perror("timer_create(SIGEV_SIGNAL)");
		return 1;
	}

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = &handler2;
	puts("Setting up timer with thread");
	if (0 > timer_create(CLOCK_MONOTONIC, &sev, &tmr2)) {
		perror("timer_create(SIGEV_THREAD)");
		return 1;
	}


	printf("cat /proc/%i/timers\n", getpid());

	sleep(3600);
}
