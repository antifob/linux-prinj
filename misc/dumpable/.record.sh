
tmuxL send-keys -t "${SESSION}:0.0" ./dumpable C-m
tmuxL send-keys -t "${SESSION}:0.1" 'strace -p $(pgrep dumpable)'

sleep 1
tmuxL send-keys -t "${SESSION}:0.1" C-m
