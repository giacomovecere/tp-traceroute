/*ICMP header file*/
/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#pragma once    /* Avoid multiple include of this file during compilation */
#include "trace_header.h"

/*NOTE the received message will have a dimension that is at most
 * 56 bytes (basing on the structure we've seen in the header)
 * but is better to provide a little of extra space in case there 
 * are extra notes in the IP headers
*/
#define MESSAGE_SIZE 80

#define ICMP_HDR_LENGTH 8

/*This class represents the received ICMP packet, this packet is composed by:
 * first 20 byte: IP header of the source of the packet
 * 8 bytes: ICMP header
 * payload:
 *  20 bytes: IP header of the source of the previous UDP packet
 *  8 bytes: UDP header 
 */

class icmpClass{

    /*dest_ip is related to the router
     *source_ip is related to the subject who does the traceroute*/
    ip* dest_ip;
    ip* sent_ip;
    int icmp_length;
    
    udphdr* udp;     //udp header
    icmp* icmp_msg;  //icmp message 

public:
    
    //in case we are building an ICMP packet to send
    icmpClass();
        
    //constructs an ICMP packet starting from infos received for traceroute
    int icmpFillTrace(char*, int);

    //constructs an ICMP packet starting from infos received for tp detect
    int icmpFillTP(char*, int);
    
    //Adapts udp field to network format
    static void adaptFromNetwork(udphdr* u);
    
    /*GET METHODS*/
    //returns the whole UDP header
    udphdr* getUDPHeader();
    
    //get ip header
    ip* getSourceIPHeader();
    ip* getDestIPHeader();
    
    //get icmp header
    icmp* getICMPheader();
    
    //get type of icmp
    int getICMPType();
    
    //get code of icmp
    int getICMPCode();
    
    int getUDPChecksum();

    /*SET METHODS*/
    void setICMPType(int );
    
    void setICMPCode(int );
    
    void setICMPPayload(char*, int );

    uint16_t getChecksum();
        
/* @Purpose: Make an icmp echo request to discover if an address (destAddr) is 
 *      classifiable or not for third part addresses discovery. It has to fill 
 *      buffer with an icmp echo request packet. Ip header is prepared by 
 *      ipManager that adds in the options field the timestamps options for 
 *      third part addresses discovery
 * @Parameters:
 *       (IN)
 *           msg: payload
 *           destAdd: destination address
 *       (OUT)
 *           len: length of the buffer
 * @Return: buffer that contains the whole icmp probe
*/
    char* makeProbe(char* payload, char* destAddr, int& len);
};

class icmpManager{
    
    //file descriptor of the socket
    int sockfd;
    //source port
    uint16_t s_port;
    //destination port
    uint16_t d_port;
    //source address
    sockaddr_in my_addr; 
    
public:
    
    //constructors
    icmpManager(){};
	icmpManager(uint16_t s);
    /* Destroyer */
    ~icmpManager();
        
    //returns the socket on which receive the ICMP
    int getSocket();
    
    //return the port
    int getSourcePort();
    int getDestPort();
    
    /* @Purpose: do the receive of an icmp packet in the udp Traceroute
     * @Parameters: 
     *          (OUT) htype represents the type of ICMP message received, 
     *                it may be PORT_UNREACHABLE, TTL_EXPIRED, ERROR
     * @Returns: addr* is the address of an addr structure 
    */
    addr* traceRecv(int* htype);
    
    /* @Purpose:receive an icmp packet for third party detection
     * @Parameters: 
     *      (IN) type of response attended (icmp echo reply or icmp port unreach)
     *       0 icmp echo reply
     *       1 icmp port unreach
     * @Returns: 
     *       number of timestamps in the ip header options field  
    */
    int tpRecv(int type);
    
    /* @Purpose: send an icmp echo request
     * @Params:
     *      (IN)
     *       msg -> payload of the message
     *       destAddr -> destination address
     * @Returns:  
     *       1 -> ok
     *       0 -> error
    */
    int tpSend(char* msg, char* destAddr);
};
