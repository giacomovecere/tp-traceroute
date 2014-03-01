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

#include "udp.h"

int main(int argc, char** argv) {
    int opt, attempts, n;
    int max_ttl = MAX_TTL_DEF;
    bool verbose = false, res;
    char* host;
    list<addr>* ip_list;
    uint16_t s_port, dest_port;
    uint16_t dest_port_ini = TRACEROUTE_PORT;
    int shift = 20;
    int last_position;
    struct addrinfo *hints, *result;

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
    host = argv[optind];
            
    /*hints = new addrinfo;
    bzero(hints, sizeof(struct addrinfo));
    hints->ai_family = AF_INET;     // 0, AF_INET, AF_INET6, etc. 
    hints->ai_socktype = SOCK_DGRAM;    // 0, SOCK_STREAM, SOCK_DGRAM, etc. 
    hints->ai_flags = AI_CANONNAME;
    //getting the information of the destination
    if ( (n = getaddrinfo(host, NULL, hints, &result)) != 0) {
        cout <<"getaddrinfo error" << endl;
        exit(EXIT_FAILURE);
    }
    
    inet_ntop(AF_INET, &(result->ai_addr), ip_host, result->ai_addrlen);
        
    cout<<result->ai_canonname<<endl;
    cout<<"traceroute to "<< result->ai_canonname;
    cout<<" ("<< ip_host <<") : "<< max_ttl;
    cout<<" hops max, "<< dest_port_ini << " initial destination port"<< endl;
    */
    // The source port depends on the PID of the instance of the traceroute
    s_port = (getpid() & 0xffff) | 0x8000;
    
    attempts = 0;
    // tries 'N_ATTEMPTS' times to do the traceroute to the destination by changing the dest. port
    
    udpRawManager urm = udpRawManager(s_port, dest_port_ini);
    urm.tpSend(host, host, (char*)&shift);
   
    return 0;
}
