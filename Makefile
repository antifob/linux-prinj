.POSIX:

DIRS=	\
	01-ptrace \
	02-ptrace-mmap \
	03-ptrace-mmap-clone \


all:
	@for dir in ${DIRS}; do \
		(cd "$${dir}" && ${MAKE}); \
	done


clean:
	@for dir in ${DIRS}; do \
		(cd "$${dir}" && ${MAKE} clean); \
	done
