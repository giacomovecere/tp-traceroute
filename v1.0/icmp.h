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
    
    //distructor
    
    //constructs an ICMP packet starting from infos received
    int icmpFill(char*, int);

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
    
    void setChecksum();

    uint16_t getChecksum();
    
    //the commented functions aren't needed now but they may be in the future
    //void setDestIPAddress(char*);
    //void setICMPPid(int p=0);
    //void setSourceIPAddress(char* );
    //void setICMPSeq(int s=0);

    friend ostream& operator<<(ostream& output, icmpClass & ic);
    
/*
    Make an icmp echo request to discover if an address (destAddr) is classifiable or not
    for third part addresses discovery
    This function receives the destination address, a timestamp, destination sockaddr_in, buffer and len
    It has to fill dest, buffer, len in order to make an icmp echo request packet
    Ip header is prepared by ipManager that adds in the options field the timestamps options for 
    third part addresses discovery
    At the end, buffer will contain the ip_header + icmp_header, len is the total packet len
*/
    void makeProbe(char* destAddr, char* timestamp, sockaddr_in& dest, char* buffer, int& len);
};

class icmpManager{
    //file descriptor of the socket
    int sockfd;
    uint16_t s_port;  //source port
    uint16_t d_port;  //destination port
    sockaddr_in* my_addr; //source address
    
public:
    
    //constructors
    icmpManager(){};
	icmpManager(uint16_t s);
        
    //returns the socket on which receive the ICMP
    int getSocket();
    
    //return the port
    int getSourcePort();
    int getDestPort();
    
    /* receive function, returns an addr structure, the pointer is useful to 
     * state the type of hop that answers, if it is an intermediate router 
     * or the final destination*/
    addr* traceRecv(int* htype);
    
    // receive an icmp echo reply
    // 
    int tpRecv();
    
    // send an icmp echo request
    // msg, destAddr, timestampAddr
    void tpSend(char*, char*, char*);
};
