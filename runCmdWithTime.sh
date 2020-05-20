#!/bin/bash

CMD=$1
ARGS=$2

SECONDS=0;
echo "cmd: $CMD $ARGS";

$CMD $ARGS;

echo "----------------> It took $SECONDS seconds";
