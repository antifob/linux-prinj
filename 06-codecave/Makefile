.POSIX:

GETSC=	getsc(){ objdump -d "$${1}" | \
		grep '^[[:space:]]\{1,\}[0-9a-f]\{1,\}:' | \
		tr '\t' '\n' | \
		grep -E '^([0-9a-f]{2} )+' | \
		xargs -n256 printf '%s ' | \
		paste -sd '' | \
		sed -e 's|[[:space:]]*$$||' | \
		sed -e 's|^|\\\\x|' -e 's| |\\\\x|g' | \
		xargs printf; }; getsc

ASM=	hello.s
SRC=	victim.c
OBJ=	${SRC:.c=.o}
SOBJ=	${ASM:.s=.o}
BIN=	${SRC:.c=}
SBIN=	${ASM:.s=}


all: ${BIN} ${SBIN}
${BIN}:

${SBIN}: ${SOBJ}
	${GETSC} $< >$@


clean:
	rm -f ${OBJ} ${SOBJ} ${BIN} ${SBIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
