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

SRC=	ulexec.s
OBJ=	${SRC:.s=.o}
BIN=	${OBJ:.o=} loader elf.st elf.st.pie elf.dy elf.dy.pie


.SUFFIXES: .s .o

.s.o:
	${CC} -c -o ${@} ${<}
.o:
	${LD} -pie -o ${@} ${<}

all: ${BIN}

${BIN}: ${OBJ}
${OBJ}: ${SRC}

elf.st: elf.c
	${CC} ${<} -static -o ${@}
elf.st.pie: elf.c
	${CC} ${<} -fpic -fpie -static-pie -o ${@}
elf.dy: elf.c
	${CC} ${<} -no-pie -o ${@}
elf.dy.pie: elf.c
	${CC} ${<} -fpic -fpie -pie -o ${@}

ulexec.bin: ulexec
	${GETSC} $< >$@
ulexec.bin.st: ulexec.bin elf.st
	cat ulexec.bin elf.st >$@
ulexec.bin.dy: ulexec.bin elf.dy
	cat ulexec.bin elf.dy >$@
ulexec.bin.st.pie: ulexec.bin elf.st.pie
	cat ulexec.bin elf.st.pie >$@
ulexec.bin.dy.pie: ulexec.bin elf.dy.pie
	cat ulexec.bin elf.dy.pie >$@

# c99 doesn't support MAP_ANON*
loader: loader.c
	gcc -o $@ $<


run: loader ulexec.bin.st ulexec.bin.dy ulexec.bin.st.pie ulexec.bin.dy.pie
	for bin in ulexec.bin.st ulexec.bin.dy ulexec.bin.st.pie ulexec.bin.dy.pie; do \
		printf '==> running %s\n' "$${bin}"; \
		./loader "$${bin}"; \
	done

debug: loader ulexec.bin.dy
	gdb --args ./loader ulexec.bin.dy

clean:
	rm -f ${BIN} ${OBJ} ulexec.bin*
