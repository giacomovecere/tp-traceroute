/*ICMP header file*/
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
    //length of the icmp
    int icmp_length;
    //udp header
    udphdr* udp;
    icmp* icmp_msg;            

public:
    
    //in case we're building an ICMP packet to send
    icmpClass();
    
    //construct an ICMP packet starting from infos received
    int icmpFill(char*, int);

    //Adapt udp field to network format
    static void adaptToNetwork(udphdr* u);
    
    /*GET METHODS*/
    //returns the whole UDP header
    udphdr* getUDPHeader();
    
    //get ip header
    ip* getSourceIPHeader();
    ip* getDestIPHeader();
    
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
};

class icmpManager{
    //file descriptor of the socket
    int sockfd;
    uint16_t s_port;
    uint16_t d_port;
    sockaddr_in* my_addr;
    
public:
    icmpManager(){};
	icmpManager(uint16_t s);
        
    //returns the socket on which receive the ICMP
    int getSocket();
    //return the port
    int getSourcePort();
    int getDestPort();
        
    addr* recv(int* htype);	
    
};
