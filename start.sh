#!/bin/sh

#This is a script for MACOS

export path=$PWD
osascript -e 'tell app "Terminal"
    do script "cd ${path} && python C.py"
end tell'

sleep 5

osascript -e 'tell app "Terminal"
    do script "cd ${path} && python server.py"
end tell'

sleep 2

osascript -e 'tell app "Terminal"
    do script "cd ${path} && python client.py"
end tell'


#This is a script for ubuntu
#python version is 2.7
# gnome-terminal -- /bin/sh -c 'python C.py; exec bash'

# sleep 5 

# gnome-terminal -- /bin/sh -c 'python server.py; exec bash'

# sleep 2

# gnome-terminal -- /bin/sh -c 'python client.py; exec bash'




