/*ICMP header file*/
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>
#include <cstring>

/*NOTE the received message will have a dimension that is at most
 * 56 bytes (basing on the structure we've seen in the header)
 * but is better to provide a little of extra space in case there 
 * are extra notes in the IP headers
*/
#define MESSAGE_SIZE 80
#define ICMP_HDR_LENGTH 8

using namespace std;

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
    int icmp_length;          //length of the icmp
    udphdr * udp;
    icmp* icmp_msg;            //icmp header
    int sockfd;              //file descriptor of the socket
    //parameters of the UDP message sent needed to do the checking
    int sent_port;
    int dest_port;

public:
    
    //construct an ICMP packet basing on source and destination
    icmpClass(int s, int d);
    //in case we're building an ICMP packet to send
    icmpClass();
    
    //construct an ICMP packet starting from infos received
    int icmpFill(char*, int);
    
    
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

    //returns the socket on which receive the ICMP
    int getSocket();

    //returns the port on which the UDP probe was sent
    //is referred to the received message
    int getPort();
    
    int getUDPChecksum();

    /*SET METHODS*/
    void setICMPType(int );
    
    void setICMPCode(int );
    
    void setICMPPayload(char*, int );
    
    void setChecksum();
    
    //the commented functions aren't needed now but they may be in the future
    //void setDestIPAddress(char*);
    //void setICMPPid(int p=0);
    //void setSourceIPAddress(char* );
    //void setICMPSeq(int s=0);

    friend ostream& operator<<(ostream& output, icmpClass & ic);
};
