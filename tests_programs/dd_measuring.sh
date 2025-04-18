#!/bin/bash
DD_INPUT_FILE="/dev/sda3"
DD_OUTPUT_FILE="/dev/null"

PATH_TO_ANALYZER_DIR="../bpf_process_tree_builder_ringbuf/code/"

NUM_OF_ITERATIONS=5
#AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES=6442450944
AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES=8589934592
#AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES=644245094
#AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES=16384
MIN_BLOCK_SIZE=128
#MAX_BLOCK_SIZE=16384
MAX_BLOCK_SIZE=128
#MAX_BLOCK_SIZE=67108864
BLOCK_SIZE_MULTIPLIER=4
#MAX_BLOCK_SIZE=2048

declare -A AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD
declare -A AVG_USER_TIME_FOR_BLOCKS_WITH_NOLOAD
declare -A AVG_KERNEL_TIME_FOR_BLOCKS_WITH_NOLOAD

declare -A AVG_REAL_TIME_FOR_BLOCKS_WITH_LOAD
declare -A AVG_USER_TIME_FOR_BLOCKS_WITH_LOAD
declare -A AVG_KERNEL_TIME_FOR_BLOCKS_WITH_LOAD

for ((number_of_run=0;number_of_run<=1;number_of_run++))
do
	if [ $number_of_run -eq 0 ]
	then
		declare -n AVG_REAL_TIME_FOR_BLOCKS=AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD
		declare -n AVG_USER_TIME_FOR_BLOCKS=AVG_USER_TIME_FOR_BLOCKS_WITH_NOLOAD
		declare -n AVG_KERNEL_TIME_FOR_BLOCKS=AVG_KERNEL_TIME_FOR_BLOCKS_WITH_NOLOAD
	else
		declare -n AVG_REAL_TIME_FOR_BLOCKS=AVG_REAL_TIME_FOR_BLOCKS_WITH_LOAD
		declare -n AVG_USER_TIME_FOR_BLOCKS=AVG_USER_TIME_FOR_BLOCKS_WITH_LOAD
		declare -n AVG_KERNEL_TIME_FOR_BLOCKS=AVG_KERNEL_TIME_FOR_BLOCKS_WITH_LOAD
		
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
	
	for ((block_size=MIN_BLOCK_SIZE;block_size<=MAX_BLOCK_SIZE;block_size*=BLOCK_SIZE_MULTIPLIER))
	do
		if [ ! -v AVG_TIME_FOR_BLOCKS[$block_size] ]; 
		then
  			AVG_REAL_TIME_FOR_BLOCKS[$block_size]=0
  			AVG_USER_TIME_FOR_BLOCKS[$block_size]=0
  			AVG_KERNEL_TIME_FOR_BLOCKS[$block_size]=0
  		fi

		printf "block $block_size bytes\n"

		for ((iteration_number=1;iteration_number<=NUM_OF_ITERATIONS;iteration_number++))
		do
			COUNT=$(($AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES / $block_size))
		
			mapfile -t CURRENT_COMMAND_RESULTS < <( { /usr/bin/time --format "%e\n%U\n%S\n" dd if=$DD_INPUT_FILE of=$DD_OUTPUT_FILE bs=$block_size''B count=$COUNT; } 2>&1 )
			
			printf "\t $iteration_number |  real (s) ${CURRENT_COMMAND_RESULTS[3]}, user (s) ${CURRENT_COMMAND_RESULTS[4]}, kernel (s) ${CURRENT_COMMAND_RESULTS[5]}\n"
			printf "\t DD_RESULT: ${CURRENT_COMMAND_RESULTS[2]}\n"
		
			AVG_REAL_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_REAL_TIME_FOR_BLOCKS[$block_size]} -v b=${CURRENT_COMMAND_RESULTS[3]} 'BEGIN {print a+b}'`
			AVG_USER_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_USER_TIME_FOR_BLOCKS[$block_size]} -v b=${CURRENT_COMMAND_RESULTS[4]} 'BEGIN {print a+b}'`
			AVG_KERNEL_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_KERNEL_TIME_FOR_BLOCKS[$block_size]} -v b=${CURRENT_COMMAND_RESULTS[5]} 'BEGIN {print a+b}'`
		done
	
		AVG_REAL_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_REAL_TIME_FOR_BLOCKS[$block_size]} -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
		AVG_USER_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_USER_TIME_FOR_BLOCKS[$block_size]} -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
		AVG_KERNEL_TIME_FOR_BLOCKS[$block_size]=`awk -v a=${AVG_KERNEL_TIME_FOR_BLOCKS[$block_size]} -v b=$NUM_OF_ITERATIONS 'BEGIN {print a/b}'`
	done
	
	if [ $number_of_run -eq 1 ]
	then
		echo "1" > runs_finished.txt
		#rm extractorlog.txt
	fi
done


RED='\033[0;31m'
NC='\033[0m'

printf "\n\n"
printf " block size, |  number of  |  Real no  | Real with |Degradation|  User no  | User with |Degradation| Kernel no |Kernel with|Degradation\n"
printf "    bytes    |   syscalls  |  load, s  |  load, s  |    , %%    |  load, s  |  load, s  |    , %%    |  load, s  |  load, s  |    , %%    \n"

for ((block_size=MIN_BLOCK_SIZE;block_size<=MAX_BLOCK_SIZE;block_size*=BLOCK_SIZE_MULTIPLIER))
do
	echo '-------------|-------------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------'
	printf '%-13s|' "$block_size"
	printf '%-13s|' "$(($AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES / $block_size * 2))"
	printf "   %-8s|   %-8s|   ${RED}%-8s${NC}|" "${AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}" "${AVG_REAL_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]}" `awk -v a=${AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]} -v b=${AVG_REAL_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]} 'BEGIN {printf "%.3f", (b - a)/a*100}'` 
	printf "   %-8s|   %-8s|   ${RED}%-8s${NC}|" "${AVG_USER_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}" "${AVG_USER_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]}" `awk -v a=${AVG_USER_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]} -v b=${AVG_USER_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]} 'BEGIN {printf "%.3f", (b - a)/a*100}'`
	printf "   %-8s|   %-8s|   ${RED}%-8s\n${NC}" "${AVG_KERNEL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}" "${AVG_KERNEL_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]}" `awk -v a=${AVG_KERNEL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]} -v b=${AVG_KERNEL_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]} 'BEGIN {printf "%.3f", (b - a)/a*100}'`
	printf "             |             |%-11s|%-11s|           |           |           |           |           |           |           \n" `awk -v a=$(($AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES / $block_size * 2)) -v b=${AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]} 'BEGIN {print a/b}'` `awk -v a=$(($AMOUNT_OF_DATA_BEING_MOVED_IN_BYTES / $block_size * 2)) -v b=${AVG_REAL_TIME_FOR_BLOCKS_WITH_LOAD[$block_size]} 'BEGIN {print a/b}'`
done

printf "\n\n"

#printf "\n\n"
#printf " block size, |   Real,   |   User,   |  Kernel,  \n"
#printf "    bytes    |     s     |     s     |     s     \n"

#for ((block_size=MIN_BLOCK_SIZE;block_size<=MAX_BLOCK_SIZE;block_size*=2))
#do
#	echo '-------------|-----------|-----------|-----------'
#	printf '    %-8s |   %-8s|   %-8s|   %-8s\n' "$block_size" "${AVG_REAL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}" "$#{AVG_USER_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}" "${AVG_KERNEL_TIME_FOR_BLOCKS_WITH_NOLOAD[$block_size]}"
#done

#printf "\n\n"

