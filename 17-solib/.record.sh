
tmuxL send-keys -t "${SESSION}:0.0" './victim | sed -e "s|/home/.*||"' C-m
tmuxL send-keys -t "${SESSION}:0.1" 'python3 inject.py ./lib.so $(pgrep victim)'

sleep 1
tmuxL send-keys -t "${SESSION}:0.1" C-m
