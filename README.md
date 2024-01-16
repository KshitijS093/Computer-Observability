# ComputerObservability
To setup on a system:
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
You need to run the following codes as sudo python3 programname.py

To get output in a single output file:
create .sh file and store all the commands and make that file executable
(To make executable :
 Chmod +x filename.sh)
(Commands inside of it:
 sudo python3 file.py >> output.txt)
call the executable file 
all result gets stored onto a particular output file 






UPDATE
1. L3 Cache Stats:- llcstat.py Everything done
2. paging Operations:-
	2.1 page faults:- pagefaults.py Done
	2.2 Re-Faulted Pges:- pagerefault Not Done
	2.3 Swap in/out stats:- swapin.py Done
3. Swap I/O overhead:- Swapiooverhead.py Done
4. User Space Memory alloc and Dealloc:- memleak.py  Done
5. VM Stats:- Direct Command for free and availaible but for rss and pss Not Working
6. Memory Management Event Tracing
	6.1 Kswapd:- kswapd.py , kswapdcompact.py Not Working
	6.2 OOM Kiler:- oomkill.py Done
	6.3 kcompact:- kcompact.py , kswapdcompact.py Not Working
7. PSI Stats:- psistat.py Direct Commands
