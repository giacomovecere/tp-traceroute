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
 * usage: traceroute [ -m <maxttl> -p <initial_port> ] <IP>
*/

#include "traceroute.h"
#include "routerDetective.h"

int main(int argc, char** argv) {
	int opt, attempts;
	int max_ttl = MAX_TTL_DEF;
	bool res;
	char* host;
	list<addr>* ip_list;
	uint16_t s_port, dest_port;
	uint16_t dest_port_ini = TRACEROUTE_PORT;
	int shift = 20;
    int last_position, len_ip;

	// All of the options are optional: both m and p require arguments
	while ((opt = getopt (argc, argv, "m:p:")) != -1) {
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
			if ((dest_port = atoi (optarg)) <= 1){
				cout << "Invalid -p value" << endl;
				exit(EXIT_FAILURE);
			}
			break;
		case '?':
			cout << "Unrecognized option: " << opt << endl;
			exit(EXIT_FAILURE);
		}
	}
	
	if(optind != argc - 1) {
		cout << "usage: traceroute [ -m <maxttl> -p <initial_port> ] <IP>"<<endl;
		exit(EXIT_FAILURE);
	}
	// ip address or hostname of the destination to reach
	len_ip = strlen(argv[optind]);
	host = new char[len_ip + 1];
    strncpy(host, argv[optind], len_ip);
    host[len_ip + 1] = '\0';
	        
    s_port = (getpid() & 0xffff) | 0x8000;
    traceroute t = traceroute(s_port, max_ttl);
    
	attempts = 0;
    // tries 'N_ATTEMPTS' times to do the traceroute to the destination by changing the dest. port
	while(attempts < N_ATTEMPTS) {
		#ifdef _DEBUG
			cout<< "Attempt n°"<<attempts + 1<<" of traceroute. IP:"<<host<<" Port:"<<dest_port_ini<<endl;
		#endif
            
        dest_port = dest_port_ini;
		
		res = t.trace(host, &dest_port);
		// if the traceroute has reached the destination, stop
		if(res == true) {
            #ifdef _DEBUG
                cout<<"Traceroute ok: destination has replied! \n";
            #endif

            cout<< "Traceroute to "<<host<<":"<<dest_port<<", "<<max_ttl<<" hops max."<<endl;
                
            t.print();
            
            ip_list = t.getArrayList(&last_position);
			
			break;
        }
        
        #ifdef _DEBUG
            t.print();
        #endif
        
        // if not, try with another initial destination port
		dest_port_ini = dest_port_ini + shift;
		s_port++;
        attempts++;
        if(attempts == N_ATTEMPTS) {
            cout << "Traceroute failed: it was not possible to reach the" 
            <<"destination after "<< N_ATTEMPTS << " attempts of traceroute"<< endl;
            return 0;
        }
        t.resetObj(s_port, max_ttl);
    }
    
    routerDetective r = routerDetective(ip_list, last_position);
    res = r.thirdPartyDetection(s_port, dest_port, host);
    if(res == true) {
        #ifdef _DEBUG
            cout<<"Third Party detection has been completed successfully!"<<endl;
        #endif
            
        cout<< "Third Party process to "<<host<<"."<<endl;
        
        r.print(host);
    }
   
	return 0;
}
