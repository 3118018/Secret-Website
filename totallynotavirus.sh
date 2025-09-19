#!/bin/bash
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SCRIPTNAME=$(basename "$0")
osascript -e "set volume output volume 100"
osascript -e "tell application \"Terminal\" to do script \"cd '$SCRIPTPATH'; sh $SCRIPTNAME\""
echo "haha"
while true
do
open https://www.youtube.com/watch?v=2qBlE2-WL60
done