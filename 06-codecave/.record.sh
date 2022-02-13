
tmuxL send-keys -t "${SESSION}:0.0" './victim' C-m
tmuxL send-keys -t "${SESSION}:0.1" 'python3 inject.py ./hello $(pgrep victim)'

sleep 3
tmuxL send-keys -t "${SESSION}:0.1" C-m
