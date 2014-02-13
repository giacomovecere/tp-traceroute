/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 * Traceroute Header File
 * 
 */
 
// #include "trace_header.h"
 #include "udp.h"

class traceroute {
    list<addr> ip_list[MAX_TTL_DEF];
	uint16_t src_port; 
	
	public:
	
	traceroute(uint16_t);
	
	list<addr> trace(char*, int);
        
    friend ostream& operator<<(ostream& output, traceroute& t);
	
};
