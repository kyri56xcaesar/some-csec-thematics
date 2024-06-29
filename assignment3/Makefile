all: logger acmonitor test_aclog

logger: logger.c
	gcc  -Wno-deprecated-declarations -g -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc -g test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -f file_*
	rm -f *.lo
	rm -f *.txt
	rm -f *.out
	rm -f *.o
	rm -f *.log
	rm -f *.key

	
