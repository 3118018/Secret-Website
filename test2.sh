SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
osascript -e "tell application \"Terminal\" to do script \"cd '$SCRIPTPATH'; sh test2.sh\""