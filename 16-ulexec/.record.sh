
tmuxL send-keys -t "${SESSION}:0.0" './loader ./ulexec.bin.dy | head -n4 | cut -d" " -f1-5'
tmuxL send-keys -t "${SESSION}:0.1" './loader ./ulexec.bin.dy.pie | head -n4 | cut -d" " -f1-5'

sleep 2
tmuxL send-keys -t "${SESSION}:0.0" C-m './loader ./ulexec.bin.st | head -n4 | cut -d" " -f1-5'
tmuxL send-keys -t "${SESSION}:0.1" C-m './loader ./ulexec.bin.st.pie | head -n4 | cut -d" " -f1-5'

sleep 2
tmuxL send-keys -t "${SESSION}:0.0" C-m
tmuxL send-keys -t "${SESSION}:0.1" C-m
