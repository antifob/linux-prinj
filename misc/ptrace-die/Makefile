.POSIX:

SRC=	die.c victim.c
BIN=	${SRC:.c=}


all: ${BIN} ${SBIN}
${BIN}:

clean:
	rm -f ${BIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
