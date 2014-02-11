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
 * 28 bytes referred to the UDP probe: 
 *     20 bytes: IP header of the source of the previous UDP packet
 *     8 bytes: UDP header 
 */


struct icmpPacket{
    
    /*dest_ip is related to the router
     *source_ip is related to the subject who does the traceroute*/
    ip* dest_ip;
    ip* sent_ip;
    udphdr * udp;
    icmp* rec_msg;  	 //icmp header
    int sockfd;              //file descriptor of the socket
    sockaddr router_source;  //filled by the sender
    
};


class icmpClass{

    icmpPacket datagram;
    //parameters of the UDP message sent needed to do the checking
    int sent_port;
    int dest_port;
    char* ipAddress;     //ip of the router that answers

public:
    icmpClass(int s, int d);

    //returns the whole buffer of the ICMP packet
    char* getBuffer();

    //returns the socket on which receive the ICMP
    int getSocket();

    //returns the IP of the source of the ICMP
    char* getIP();

    //returns the port on which the UDP probe was sent
    //is referred to the received message
    int getPort();

    //receive the ICMP packet
    int recv(int* );

    ostream& operator<<(ostream& output, const icmpClass & ic);
};
