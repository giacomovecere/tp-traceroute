/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 * routerDetective Header File
 * 
 */

#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "trace_header.h"

using namespace std;

 class routerDetective {
    //list<addr> array_list[MAX_TTL_DEF];
    list<addr>* array_list;
    int last_position;
    
public:
    
    //Constructor of the class
    routerDetective( list<addr>*, int);
    
    //Sends ICMP echo request to each intermediate hop
    bool echoReqReply(char*, uint16_t);
    
    /*Receives ICMP echo response from intermediate hops and
      send UDP probes to each classifiable hop*/
    list<addr>* hopsClassificability(uint16_t, char*, uint16_t);
    
    /*Receives an ICMP response and set it intermediate hops as TP or OP */
    bool thirdPartyDetection(uint16_t, uint16_t, char*);
    
    //Prints the elements of the list 
    void print();
};
