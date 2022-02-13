.POSIX:

DIRS=	\
	01-ptrace \
	02-ptrace-mmap \
	03-ptrace-mmap-fork \
	04-hollowing \
	05-unused \
	06-codecave \
	07-clone \
	08-signals \
	09-timers \
	10-got \
	11-vdso \
	12-stack \
	13-procmem \
	14-pvmw \
	15-int3 \
	16-ulexec \
	17-solib \


all:
	@for dir in ${DIRS}; do \
		(cd "$${dir}" && ${MAKE}); \
	done


clean:
	@for dir in ${DIRS}; do \
		(cd "$${dir}" && ${MAKE} clean); \
	done
