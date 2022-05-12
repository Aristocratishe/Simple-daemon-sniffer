#include <iostream>
#include"sniffer.h"


int main(int, char**) 
{
	pid_t pid, sid;

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	umask(0);

	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	if ((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	pcap_if_t *alldevsp , *device;
	pcap_t *handle;

	char errbuf[100] , *devname;

	devname = pcap_lookupdev(errbuf);
	if(devname == NULL)
	{
		exit(EXIT_FAILURE);
	}

	handle = pcap_open_live(devname, 65536, 1, -1, errbuf);
	if (handle == NULL) 
	{
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(handle , -1 , process_packet, NULL);

	sleep(30);

	return 0;
}

