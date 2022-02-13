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
SRC=	inject.c victim.c
AOBJ=	${ASM:.s=.o}
BIN=	${SRC:.c=}
ABIN=	${ASM:.s=}


all: ${BIN} ${ABIN}
${BIN}:

${ABIN}: ${AOBJ}
	${GETSC} $< >$@


clean:
	rm -f ${AOBJ} ${BIN} ${ABIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
