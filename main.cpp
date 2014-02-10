/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "trace_header.h"
#include "traceroute.h"

int main(int argc, char** argv) {
	int opt;
	int max_ttl = MAX_TTL_DEF;
	int n_probe = N_PROBE_DEF;
	bool verbose = false;
	struct addrinfo *a_info;
	char ip_host[30];
	address* ip_list;
	
	// All of the options are optional: m and p require arguments
	while ((opt = getopt (argc, argv, "m:p:v")) != -1) {
		switch (opt) {
		// Max number of Time to Leave
		case 'm':
			if ((max_ttl = atoi (optarg)) <= 1) {
				cerr << "Invalid -m value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
		// Number of probes to send
		case 'p':
			if ((n_probe = atoi (optarg)) <= 1){
				cerr << "Invalid -p value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
		// Verbose output	
		case 'v':
			verbose = true;
		break;
		case '?':
			cerr << "Unrecognized option: " << opt << endl;
			exit(EXIT_FAILURE);
		}
	}
	
	if(optind != argc - 1) {
		cerr << "usage: traceroute [ -m <maxttl> -p <n_probe> -v ] <hostname>");
		exit(EXIT_FAILURE);
	}
	host = argv[optind];
	a_info = Host_serv(host, NULL, AF_INET, SOCK_DGRAM);
	
	inet_ntop(AF_INET, &(a_info->ai_addr), ip_host, a_info->addrlen);
	cout<<"traceroute to "<< a_info->ai_canonname ? a_info->ai_canonname : ip_host <<" ( "<< ip_host <<" ) : "<< max_ttl <<
	" hops max, "<< n_probe << " number of probes to send"<< endl;
	
	// The source port depends on the PID of the instance of the traceroute
	src_port = (getpid() & 0xffff) | 0x8000;
	
	traceroute t = new traceroute(src_port);
	ip_list = t.trace(ip_host, max_ttl, n_probe);
	// [Print of the ip addresses from ip_list]
	
	return 0;
}
