#!/bin/sh
set -eu

PROGBASE=$(d=$(dirname -- "${0}"); cd "${d}" && pwd)
PROJROOT=$(cd "${PROGBASE}/.." && pwd)
CASTNAME=$(basename $(pwd))


if [ ! -d "${PROJROOT}/recording/venv" ]; then
	python3 -mvenv "${PROJROOT}/recording/venv"
fi

. "${PROJROOT}/recording/venv/bin/activate"
pip install -r "${PROJROOT}/recording/requirements.txt"


SESSION=s
rm -f "${CASTNAME}.cast.tmp"
asciinema rec --overwrite --cols 80 --rows 25 -c "tmux -L ${CASTNAME} -f ${PROGBASE}/tmux.conf new-session -s ${SESSION}" "${CASTNAME}.cast.tmp" &
pid=$!

tmuxL() {
	tmux -L "${CASTNAME}" "${@}"
}

sleep 1
tmuxL split-window -t "${SESSION}:0" -v
sleep 1

. ./.record.sh

sleep 8
tmuxL kill-window -t "${SESSION}:0"
wait $pid


# Remove the last 2 lines
head -n -2 "${CASTNAME}.cast.tmp" >"${CASTNAME}.cast"
rm -f "${CASTNAME}.cast.tmp"

reset
