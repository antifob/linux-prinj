.POSIX:

SRC=	dumpable.c
OBJ=	${SRC:.c=.o}
BIN=	${SRC:.c=}


all: ${BIN}
${BIN}: ${OBJ}
${OBJ}: ${SRC}

clean:
	rm -f ${OBJ} ${BIN}
