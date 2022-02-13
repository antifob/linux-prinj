
tmuxL send-keys -t "${SESSION}:0.0" './hollow /bin/ls ./hello' C-m
tmuxL send-keys -t "${SESSION}:0.1" 'ps a | grep hollowed'

sleep 3
tmuxL send-keys -t "${SESSION}:0.1" C-m
