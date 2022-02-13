.POSIX:

ASM=	tracee.s
SRC=	tracer.c
AOBJ=	${ASM:.s=.o}
BIN=	${SRC:.c=}
ABIN=	${ASM:.s=}


all: ${BIN} ${ABIN}

${ABIN}: ${AOBJ}
	${LD} -o $@ $<

clean:
	rm -f ${AOBJ} ${BIN} ${ABIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
