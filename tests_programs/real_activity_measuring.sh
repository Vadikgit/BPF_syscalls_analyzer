#!/bin/bash
#PATH_TO_REP="https://github.com/strace/strace.git"
#REP_NAME="strace"
#PATH_TO_REP="https://github.com/libbpf/libbpf-bootstrap.git"
#REP_NAME="libbpf-bootstrap"
PATH_TO_ANALYZER_DIR="../bpf_process_tree_builder_ringbuf/code"

NUM_OF_ITERATIONS=10

declare AVG_REAL_TIME_WITH_NOLOAD=0
declare AVG_USER_TIME_WITH_NOLOAD=0
declare AVG_KERNEL_TIME_WITH_NOLOAD=0

declare AVG_REAL_TIME_WITH_LOAD=0
declare AVG_USER_TIME_WITH_LOAD=0
declare AVG_KERNEL_TIME_WITH_LOAD=0

for ((number_of_run=0;number_of_run<=1;number_of_run++))
do
	if [ $number_of_run -eq 0 ]
	then
		declare -n AVG_REAL_TIME=AVG_REAL_TIME_WITH_NOLOAD
		declare -n AVG_USER_TIME=AVG_USER_TIME_WITH_NOLOAD
		declare -n AVG_KERNEL_TIME=AVG_KERNEL_TIME_WITH_NOLOAD
	else
		declare -n AVG_REAL_TIME=AVG_REAL_TIME_WITH_LOAD
		declare -n AVG_USER_TIME=AVG_USER_TIME_WITH_LOAD
		declare -n AVG_KERNEL_TIME=AVG_KERNEL_TIME_WITH_LOAD
		
		CURRENT_BASH_PID=$$
		CURRENT_PWD=`pwd`
		
		echo "0" > starting_finished.txt
		echo "0" > runs_finished.txt

		gnome-terminal --tab -x bash -c " cd $PATH_TO_ANALYZER_DIR; ./analyzer -start -pid $CURRENT_BASH_PID; cd $CURRENT_PWD; echo \"1\" > starting_finished.txt; while [ \`cat runs_finished.txt\` = \"0\" ]; do sleep 1; echo ...; done; rm runs_finished.txt; cd $PATH_TO_ANALYZER_DIR; ls; ./analyzer -stop; sleep 5; "
		
		while [ `cat starting_finished.txt` = "0" ]
		do
			sleep 1;
		done
		
		rm starting_finished.txt
	fi
	
	for ((iteration_number=1;iteration_number<=NUM_OF_ITERATIONS;iteration_number++))
	do
		#mapfile -t CURRENT_COMMAND_RESULTS < <( { /usr/bin/time --format "%e\n%U\n%S\n" git clone --quiet $PATH_TO_REP; } 2>&1 )
		mapfile -t CURRENT_COMMAND_RESULTS < <( { /usr/bin/time --format "%e\n%U\n%S\n" ./real_activity.sh; } 2>&1 )
		
		printf "\t $iteration_number |  real (s) ${CURRENT_COMMAND_RESULTS[0]}, user (s) ${CURRENT_COMMAND_RESULTS[1]}, kernel (s) ${CURRENT_COMMAND_RESULTS[2]}\n"
		#printf "0: ${CURRENT_COMMAND_RESULTS[0]}, 1: ${CURRENT_COMMAND_RESULTS[1]}, 2: ${CURRENT_COMMAND_RESULTS[2]}, 3: ${CURRENT_COMMAND_RESULTS[3]}, 4: ${CURRENT_COMMAND_RESULTS[4]},\n"
		
		
		AVG_REAL_TIME=`awk -v a=$AVG_REAL_TIME -v b=${CURRENT_COMMAND_RESULTS[0]} 'BEGIN {print a+b}'`
		AVG_USER_TIME=`awk -v a=$AVG_USER_TIME -v b=${CURRENT_COMMAND_RESULTS[1]} 'BEGIN {print a+b}'`
		AVG_KERNEL_TIME=`awk -v a=$AVG_KERNEL_TIME -v b=${CURRENT_COMMAND_RESULTS[2]} 'BEGIN {print a+b}'`
	done
	
	AVG_REAL_TIME=`awk -v a=$AVG_REAL_TIME -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
	AVG_USER_TIME=`awk -v a=$AVG_USER_TIME -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
	AVG_KERNEL_TIME=`awk -v a=$AVG_KERNEL_TIME -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
	
	if [ $number_of_run -eq 1 ]
	then
		echo "1" > runs_finished.txt
		#rm extractorlog.txt
	fi
done


RED='\033[0;31m'
NC='\033[0m'

printf "\n\n"
printf " Real no  | Real with |Degradation|  User no  | User with |Degradation| Kernel no |Kernel with|Degradation\n"
printf " load, s  |  load, s  |    , %%    |  load, s  |  load, s  |    , %%    |  load, s  |  load, s  |    , %%    \n"

echo '----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------'
printf "  %-8s|   %-8s|   ${RED}%-8s${NC}|" "$AVG_REAL_TIME_WITH_NOLOAD" "$AVG_REAL_TIME_WITH_LOAD" `awk -v a=$AVG_REAL_TIME_WITH_NOLOAD -v b=$AVG_REAL_TIME_WITH_LOAD 'BEGIN {printf "%.3f", (b - a)/a*100}'` 
printf "   %-8s|   %-8s|   ${RED}%-8s${NC}|" "$AVG_USER_TIME_WITH_NOLOAD" "$AVG_USER_TIME_WITH_LOAD" `awk -v a=$AVG_USER_TIME_WITH_NOLOAD -v b=$AVG_USER_TIME_WITH_LOAD 'BEGIN {printf "%.3f", (b - a)/a*100}'`
printf "   %-8s|   %-8s|   ${RED}%-8s\n${NC}" "$AVG_KERNEL_TIME_WITH_NOLOAD" "$AVG_KERNEL_TIME_WITH_LOAD" `awk -v a=$AVG_KERNEL_TIME_WITH_NOLOAD -v b=$AVG_KERNEL_TIME_WITH_LOAD 'BEGIN {printf "%.3f", (b - a)/a*100}'`

printf "\n\n"

