#!/bin/bash

NUM_OF_LEVELS=7
BRANCHING_DEGREE=2

recProcedure(){
     for ((number=1;number<=$BRANCHING_DEGREE;number++))
     do
     	if [ $NUM_OF_LEVELS -gt $1 ]
     	then
     	i=$1
     	((i++))
     	bash -c "source branching_shells.sh; ls; ps; recProcedure $i; exit"
     	fi
     done
}

declare -f -x recProcedure
