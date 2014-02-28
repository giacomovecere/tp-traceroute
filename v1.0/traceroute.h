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
 
#include "udp.h"
#include "icmp.h"

class traceroute {
    list<addr> array_ip_list[MAX_TTL_DEF];
    uint16_t src_port; 
    int last_position;
    
    public:
    
    traceroute(uint16_t);
    ~traceroute();
    
    /* computes the traceroute to the destination: 'ip_address'
    * 'max_ttl' indicates the max value for the TTL
    * 'dest_port_ini' is the first value of the destination port. It is going to be incremented 
    * for finding one from which the router along the path will reply */
    bool trace(char*, int, uint16_t*);
    
    /* Returns the pointer of the array that contains the lists of the 'addr' elements */
    list<addr>* getArrayList(int*);
    
    /* Prints the elements of the list stored */
    void print();
	
};

/* Performs the subtraction between the structure 'in' and 'out' */
void tv_sub(timeval*, timeval);

/* Finds if there is an element with the given checksum and updates the timeval field */
bool change_timeval(addr*, list<addr>::iterator, list<addr>::iterator);
