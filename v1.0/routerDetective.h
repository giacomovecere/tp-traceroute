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
#pragma once    /* Avoid multiple include of this file during compilation */
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
    
    /*Coordinates the classification of hops discovered by traceroute towards the destination.
     Hops are classified as: NON CLASSIFIABLE, ON PATH or THIRD PARTY*/
    bool thirdPartyDetection(uint16_t, uint16_t, char*);
    
    //Prints the elements of the list 
    void print();
};

//Sends an ICMP echo request to each intermediate hop and receives an icmp echo reply
int echoReqReply(char*, uint16_t);

/*Sends UDP probes to classifiable hops and receives an icmp port unreach from intermediate hops*/
int hopsClassificability(uint16_t, uint16_t, char*, char*);
    