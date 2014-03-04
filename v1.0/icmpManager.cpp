/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "icmp.h"

icmpManager::icmpManager(uint16_t s){
    s_port = s;
    int one = 1;
    
    //socket that receives icmp packet
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    //set the option to put our IP header not the one made by the kernel
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one , sizeof(one)) < 0) 
        cout<<"ERROR\n";
    
    if(sockfd < 0 || one < 0) {
        cout<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
    
    //init struct for binding
    my_addr.sin_family = AF_INET; 
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    my_addr.sin_port = htons(s_port);
    
    //bind to source port
    bind(sockfd, (sockaddr*)&my_addr, sizeof(my_addr));
}

int icmpManager::getSocket() { return sockfd; }

//referred to the source
int icmpManager::getSourcePort() { return s_port; }

//referred to the destination
int icmpManager::getDestPort() {return d_port;}

/* @Purpose: do the receive of an icmp packet in the udp Traceroute
 * @Parameters: 
 *          (OUT) htype represents the type of ICMP message received, 
 *                it may be PORT_UNREACHABLE, TTL_EXPIRED, ERROR
 * @Returns: addr* is the address of an addr structure 
*/
addr* icmpManager::traceRecv(int* htype){
    
    //buffer in which put the received message
    char buffer[MESSAGE_SIZE];
    //rm stands for remote
    sockaddr_in rm_addr;
    socklen_t rm_addr_size;
    
    memset((char *)&rm_addr, 0, sizeof(rm_addr));
    
    // to get the right ip address from the recvfrom function
    rm_addr_size = sizeof(struct sockaddr_in);
    //receive the response message
    int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)&rm_addr,
                       &rm_addr_size);
    if(ret != -1) {
        icmpClass* icmpPkt = new icmpClass();
        //fill object with received message  
        int fill_ret = icmpPkt->icmpFillTrace(buffer,MESSAGE_SIZE);
        if(fill_ret < 0) {
            cout<<"icmpManager::traceRecv error"<<endl;
            exit(EXIT_FAILURE);
        }
        
        /*Change byte ordering according to our host 
        and then retrieve port destination*/
        icmpPkt->adaptFromNetwork(icmpPkt->getUDPHeader());
        d_port = icmpPkt->getUDPHeader()->dest;

        addr* address = new addr;
        //set router ip address
        inet_ntop(AF_INET, &(rm_addr.sin_addr), address->ip, LENGTH_IP_ADDRESS);
        address->ip[strlen(address->ip)+1] = '\0';
        //set current time
        gettimeofday (&(address->time), NULL);
        address->checksum = icmpPkt->getUDPChecksum();
        address->ret = false;

        //check if intermediate router reached 
        if(icmpPkt->getICMPType() == ICMP_TIME_EXCEEDED && 
            icmpPkt->getICMPCode() == ICMP_TIMXCEED_INTRANS){ 
            *htype = INTERMEDIATE_ROUTER;
        }
        //check if final destination reached 
        else if(icmpPkt->getICMPType() == ICMP_UNREACH){
            *htype = FINAL_DESTINATION;
        } 
        else{
            //error
            *htype = -1;
        }

        delete icmpPkt;
        return address;
    }
    else{
        //error
        return NULL;
    }
}

/* @Purpose: send an icmp echo request
 * @Params:
 *      (IN)
 *       msg -> payload of the message
 *       destAddr -> destination address
 * @Returns:  
 *       1 -> ok
 *       0 -> error
 */
int icmpManager::tpSend(char* payload, char* destAddr){
    
    //destination address in network format
    sockaddr_in dest;
    //buffer is where we put the whole packet, including th IP header
    char* buffer;
    int len;
    
    //create a new icmp packet
    icmpClass* icmpPkt = new icmpClass();    
    buffer = icmpPkt->makeProbe(payload, destAddr, len);

    //destination structure initialization
    dest.sin_family = AF_INET;                
    dest.sin_port = htons(0);        
    inet_pton(AF_INET, destAddr, &dest.sin_addr);
    
    //send operation
    int ret =  sendto(sockfd,buffer,len,0,(sockaddr *)&dest,sizeof(sockaddr));
    delete icmpPkt;
    //check the result of the send
    if(ret > 0) {
        return 1; //ok
    }
    else {
        return 0; //error
    }
}

/* @Purpose:receive an icmp packet for third party detection
 * @Parameters: 
 *      (IN) type of response attended (icmp echo reply or icmp port unreach)
 *       0 icmp echo reply
 *       1 icmp port unreach
 * @Returns: 
 *       number of timestamps in the ip header options field  
*/
int icmpManager::tpRecv(int type){
    
    char buffer[MESSAGE_SIZE];
    sockaddr_in rm_addr;
    socklen_t rm_addr_size;
    int timestamps = 0;
    
    memset((char *)&rm_addr, 0, sizeof(rm_addr));
    
    // to get the right ip address from the recvfrom function
    rm_addr_size = sizeof(struct sockaddr_in);
    
    // receive the response message
    int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)&rm_addr,&rm_addr_size);
    
    if(ret != -1) {
        icmpClass* icmpPkt = new icmpClass();
        //fill object with received message
        int fill_ret = icmpPkt->icmpFillTP(buffer,MESSAGE_SIZE);
        if(fill_ret != -1){
            //check if what we receive is what we attend 
            if((icmpPkt->getICMPType() == ICMP_ECHOREPLY && type == 0)
              ||(icmpPkt->getICMPType() == ICMP_UNREACH && type == 1)){
                //get the ip header of received packet
                
//TODO create an ipClass from the received IP
                ip* ip_hdr = icmpPkt->getDestIPHeader();
                //bytes length of ip header
                int ip_hdr_len = ip_hdr->ip_hl << 2;
                //if ip_hdr_len > 20 there is something in the options field
                if(ip_hdr_len > 20){
                    ip_timestamp* timestamp_opt = (ip_timestamp*)(ip_hdr + 20);
                    //check if option is a timestamp
                    if(timestamp_opt->ipt_code == IPOPT_TS){
                        //count the number of timestamps in the option
                        //I suppose that they can be counted using 
                        //timestamp_opt->ipt_len
                        for(int i=1; i<8; i+=2) {
                            if(timestamp_opt->data[i] != 0)
                                timestamps++;
                            else
                                break;
                        }
                        delete icmpPkt;
                        return timestamps;
                    }
                }
            }       
        }
        delete icmpPkt;
    }
    return -1;
}

/* Destroyer */
icmpManager::~icmpManager() {
    close(sockfd);
}