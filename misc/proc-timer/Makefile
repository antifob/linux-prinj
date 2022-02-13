.POSIX:

SRC=    timers.c
BIN=    ${SRC:.c=}
LIBS=	-lrt


all: ${BIN} ${SBIN}
${BIN}:

clean:
	rm -f ${BIN}


.SUFFIXES: .c
.c:
	${CC} -o ${@} ${<} ${LIBS}
