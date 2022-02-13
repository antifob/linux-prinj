.POSIX:

GETSC=  getsc(){ objdump -d "$${1}" | \
		grep '^[[:space:]]\{1,\}[0-9a-f]\{1,\}:' | \
		tr '\t' '\n' | \
		grep -E '^([0-9a-f]{2} )+' | \
		xargs -n256 printf '%s ' | \
		paste -sd '' | \
		sed -e 's|[[:space:]]*$$||' | \
		sed -e 's|^|\\\\x|' -e 's| |\\\\x|g' | \
		xargs printf; }; getsc

SRC=	lib.c victim.c
BIN=	lib.so victim


all: ${BIN}

lib.so: lib.c
	${CC} -shared -o $@ $<

clean:
	rm -f ${BIN} ${OBJ}
