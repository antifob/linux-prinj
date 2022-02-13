.POSIX:

SRC=	seize.c
BIN=	${SRC:.c=}


all: ${BIN} ${SBIN}
${BIN}:

clean:
	sudo rm -f ${BIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
