
tmuxL send-keys -t "${SESSION}:0.0" './victim' C-m
tmuxL send-keys -t "${SESSION}:0.1" './inject ./hello $(pgrep victim)'

sleep 2
tmuxL send-keys -t "${SESSION}:0.1" C-m

sleep 1
tmuxL send-keys -t "${SESSION}:0.1" 'ps -eL | grep victim' C-m
