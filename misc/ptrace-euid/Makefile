.POSIX:

SRC=	ptrace.c
BIN=	\
	${SRC:.c=} \
	ptrace-cap ptrace-groot ptrace-group ptrace-uroot ptrace-user


all: ${BIN} ${SBIN}
${BIN}:

ptrace-cap: ptrace
	cp $< $@
	sudo setcap cap_net_raw=ep $@

ptrace-groot: ptrace
	sudo cp $< $@
	sudo chown 0 $@
	sudo chmod g+s $@

ptrace-group: ptrace
	cp $< $@
	chmod g+s $@

ptrace-uroot: ptrace
	sudo cp $< $@
	sudo chown 0 $@
	sudo chmod u+s $@

ptrace-user: ptrace
	cp $< $@
	chmod u+s $@

clean:
	sudo rm -f ${BIN}


.SUFFIXES: .s.o
.s.o:
	${CC} -c -o ${@} ${<}
