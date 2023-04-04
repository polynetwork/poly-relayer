
# 0: poly to starcoin, 1: starcoin to poly,
# if you want to specific a scanning height, please use this command:
# `/server --config config.devnet.poly-starcoin.conf.json --roles config.devnet.poly-starcoin.roles.json settxblock -chain 0 -height <height_num>`
ROLE=$1
START_HEIGHT=$2

set -e

SCRIPT_PATH="$( cd "$( dirname "$0" )" >/dev/null 2>&1 && pwd )"

docker-compose down
docker-compose up -d

if [ "${ROLE}" = "1" ]
then
  CONFIG_FILE=config.devnet.poly-starcoin.conf.json
  ROLE_FILE=config.devnet.poly-starcoin.roles.json
else
  CONFIG_FILE=config.devnet.starcoin-poly.conf.json
  ROLE_FILE=config.devnet.starcoin-poly.roles.json
fi

cd "$SCRIPT_PATH/.." || exit
#gvm use system
./build.sh testnet
./server --config $CONFIG_FILE --roles $ROLE_FILE settxblock -chain 0 -height $START_HEIGHT
./server --config $CONFIG_FILE --roles $ROLE_FILE