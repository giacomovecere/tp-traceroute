/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

/*
 * usage: traceroute [ -m <maxttl> -p <initial_port> -v ] <hostname>
*/

#include "traceroute.h"

int main(int argc, char** argv) {
	int opt, attempts, n;
	int max_ttl = MAX_TTL_DEF;
	bool verbose = false, res;
	char ip_host[30];
	char* host;
	list<addr> ip_list;
	uint16_t s_port;
	uint16_t dest_port_ini = 33434; //32768 + 666?
	int shift = 20;
	struct addrinfo	hints, *result;

	// All of the options are optional: m and p require arguments
	while ((opt = getopt (argc, argv, "m:p:v")) != -1) {
		switch (opt) {
		// Max number of Time to Leave
		case 'm':
			if ((max_ttl = atoi (optarg)) <= 1) {
				cout << "Invalid -m value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
		// Number of the initial port
		case 'p':
			if ((dest_port_ini = atoi (optarg)) <= 1){
				cout << "Invalid -p value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
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
		cout << "usage: traceroute [ -m <maxttl> -p <initial_port> -v ] <hostname>";
		exit(EXIT_FAILURE);
	}
	host = argv[optind];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;		/* 0, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = SOCK_DGRAM;	/* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ( (n = getaddrinfo(host, NULL, &hints, &result)) != 0) {
		cout <<"getaddrinfo error" << endl;
		exit(EXIT_FAILURE);
	}
	
	inet_ntop(AF_INET, &(result->ai_addr), ip_host, result->ai_addrlen);
	cout<<"traceroute to "<< result->ai_canonname <<" ( "<< ip_host <<" ) : "<< max_ttl <<
	" hops max, "<< dest_port_ini << " initial destination port"<< endl;
	
	/*cout<<"traceroute to "<< result->ai_canonname ? result->ai_canonname : ip_host <<" ( "<< ip_host <<" ) : "<< max_ttl <<
	" hops max, "<< dest_port_ini << " initial destination port"<< endl;*/
	
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
		#ifdef _DEBUG
			cout<<"First attempt of traceroute. ip: "<<ip_host<<" port: "<<dest_port_ini<<endl;
		#endif
		
		res = t.trace(ip_host, max_ttl, dest_port_ini);
		// if the traceroute has reached the destination, we can stop
		if(res == true)
			break;
		
		// if not, we try with another initial destination port
		dest_port_ini = dest_port_ini + shift;
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
