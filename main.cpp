/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "traceroute.h"

int main(int argc, char** argv) {
	int opt, attempts;
	int max_ttl = MAX_TTL_DEF;
	//int n_probe = N_PROBE_DEF;
	bool verbose = false, res;
	struct addrinfo *a_info;
	char ip_host[30];
	char* host;
	list<addr> ip_list[MAX_TTL_DEF];
	uint16_t s_port;
	uint16_t dest_port_ini = 32768 + 666; //NOTE possible optimization

	// All of the options are optional: m and p require arguments
	while ((opt = getopt (argc, argv, "m:v")) != -1) {
		switch (opt) {
		// Max number of Time to Leave
		case 'm':
			if ((max_ttl = atoi (optarg)) <= 1) {
				cout << "Invalid -m value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
		/*// Number of probes to send
		case 'p':
			if ((n_probe = atoi (optarg)) <= 1){
				cout << "Invalid -p value" << endl;
				exit(EXIT_FAILURE);
			}
			break;*/
		// Verbose output	
		case 'v':
			verbose = true;
		break;
		case '?':
			cout << "Unrecognized option: " << opt << endl;
			exit(EXIT_FAILURE);
		}
	}
	
	if(optind != argc - 1) {
		cout << "usage: traceroute [ -m <maxttl> -v ] <hostname>";
		exit(EXIT_FAILURE);
	}
	host = argv[optind];
	/*a_info = Host_serv(host, NULL, AF_INET, SOCK_DGRAM);
	
	inet_ntop(AF_INET, &(a_info->ai_addr), ip_host, a_info->addrlen);
	cout<<"traceroute to "<< a_info->ai_canonname ? a_info->ai_canonname : ip_host <<" ( "<< ip_host <<" ) : "<< max_ttl <<
	" hops max, "<< n_probe << " number of probes to send"<< endl;
	*/
	// The source port depends on the PID of the instance of the traceroute
	s_port = (getpid() & 0xffff) | 0x8000;
	
	traceroute t = traceroute(s_port);
	
	attempts = 0;
	while(attempts < N_ATTEMPTS) {
		res = t.trace(ip_host, max_ttl, dest_port_ini);
		if(res == true)
			break;
		
		dest_port_ini = dest_port_ini + 10; // 10 is a random value
		attempts++;
	}
	
	if(attempts == N_ATTEMPTS)
		cout << "Traceroute failed: it was not possible to reach the destination after "<< N_ATTEMPTS << " attempts"<< endl;
	else {
		ip_list = t.getList();
		// [Print of the ip addresses from ip_list]
	}
	
	return 0;
}
