/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "traceroute.h"

void tv_sub(timeval *out, timeval *in) {
	if ( (out->tv_usec = in->tv_usec - out->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec = in->tv_sec - out->tv_sec;
}

 /* function that finds if there is a packet in the list with a checksum that is equal to 
 * the one that is passed on the function */
bool find_checksum(uint16_t checksum, list<addr>::iterator start, list<addr>::iterator end)
{
        addr* element;
        list<addr>::iterator p;
        
        // empty list
        if(start == end)
                return false;

        for(p = start; p != end; p++){
                *element = *p;
                if(element->checksum == checksum)
                        return true;
        }
        return false;
}

/* function that changes the timeval given the checksum */

bool change_timeval(addr address, 
                    list<addr>::iterator start, list<addr>::iterator end){
        //addr* element;
        list<addr>::iterator p;
        
        if(start == end)
                return false;

        for(p=start; p!= end; p++){
                //element = p;
                if(p->checksum == address.checksum){
                    p->ret = true;
                    tv_sub(&p->time, &address.time);
                    memcpy(p->ip, address.ip);
                    return true;
                }
        }
        return false;
}

traceroute::traceroute(uint16_t s_port) {
    src_port = s_port;
}

bool traceroute::trace(char* ip_address, int max_ttl, uint16_t dest_port_ini) {
    int payload = 1; //initial payload
    int ttl;
    int n_receive = 0; //makes it easy to count the number of received packets
    
    //NOTE this list part will be used to storage the info received
    //and to print them eventually
    addr* received;
    list<addr>::iterator p_iterator;
    
    //create a new icmpManager and manage the file descriptor associated
    icmpManager iManager = icmpManager(src_port);
    int socket = iManager.getSocket(); //get the file descriptor which needs to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    fdmax = socket;
    bool packets_in_time = true, done = false;
    int type; 
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
	
    /* this variable is used to state which will be the port to be used for the 
     * n step, when n>1 */
    uint16_t rec_port = 0;
            
    //vector of used dest port, useful for the icmp
    uint16_t dest_port;
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //address when ttl=1
    
    // udpManager to manage the udp packets are going to be sent
    udpManager uManager = udpManager(src_port);
    
    FD_SET(socket, &master);
    read_fds=master;
    for(ttl=1; ttl < max_ttl && done == false; ttl++) {
		#ifdef _DEBUG
			cout<<"ttl-for. ttl = "<< ttl <<endl;
		#endif
		
        /* NOTE: first of all send the packets to the destination*/
        
        // If ttl = 1, it sends 'N_PROBE_DEF' probes with different dest. ports
        if(ttl == 1) {
            for(int i = 0; i < N_PROBE_DEF; i++) {  
				#ifdef _DEBUG
					cout<<"N_PROBE-for. i = "<< i <<" ttl = "<< ttl <<endl;
				#endif
							 
                dest_port = dest_port_ini + i;
                // each packet has different payload and different dest. port
                uManager.send(ip_address, dest_port, ttl, payload++, 1, &address_ttl_1);
                array_ip_list[ttl].push_back(address_ttl_1);
            }
        }
        else {
			if(rec_port != 0) {
				#ifdef _DEBUG
					cout<<"Sending "<< (int)N_PROBE_DEF <<" packets to "<< rec_port <<" destination port"<<endl;
				#endif
				
				/* it send 'N_PROBE_DEF UDP packets to the destination
				 * each packet has different payload but same dest. port */
				uManager.send(ip_address, rec_port, ttl, payload, N_PROBE_DEF, address_vector);
                payload += 20;  
			
				for(int i = 0; i < N_PROBE_DEF; i++) {
					// it puts the 'addr' elements filled by the send method in the list
					array_ip_list[ttl].push_back(address_vector[i]);
				}
			}
		}
        
        //receive port set to 0 to check if any ICMP message arrives
        rec_port = 0;
        
        // loop until we receive all of the 'N_PROBE_DEF' packets or the time expires
        while(packets_in_time) {
            
            /*received all the messages
            if(n_receive == N_PROBE_DEF) 
				break;*/
            
            //NOTE: now to the receive of the icmp packets
            if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
                cerr<<"select error\n";
                exit(1);
            }
            if(FD_ISSET(socket, &read_fds)) {
                received = iManager.recv(&type); //receive the icmp packet
                
                //received the structure with all the fields we are interested
                if (rec_port == 0) 
                    rec_port = iManager.getDestPort(); 
                
                //check if type is right for my purpses
                if(type == INTERMEDIATE_ROUTER || type == FINAL_DESTINATION) {
                    #ifdef _DEBUG
                        fprintf(stdout, "Checksum to find: %4x \n", received->checksum);
                        cout<<endl;
                    #endif		    
                    /* modify the element in the list only if the packet received belongs to that 
                     * TTL "slot time" */
                    if(change_timeval(received, array_ip_list[ttl].begin(), 
                        array_ip_list[ttl].end()))
                        
                        n_receive++;
                }
                
                if(type == -1) 
                    cout<<"Error receiving the packet\n";
                
                if(n_receive == N_PROBE_DEF){ 
                    if(type == FINAL_DESTINATION) done = true;
                    break;
                }
            }
            
            // this means time expired
            else {
                //if we did not receive any packets we need to restart the traceroute (with another dest. port)
                if(n_receive == 0) {
                    cout<<"No messages reached destination: TRACEROUTE FAILED! \n";
                    return false;
                }
                else {
                    if(type == FINAL_DESTINATION) done = true;
                    packets_in_time = false;
                }
            }
        //print the list of addr
        }
        packets_in_time = true;
        n_receive = 0;
        timeout.tv_sec = TIMEOUT_SELECT;
        timeout.tv_usec = 0;
        type = 2;
    }
    
    return true;   
}

/* Returns the pointer of the array that contains the lists of the 'addr' elements */
list<addr>* traceroute::getArrayList() {
	return array_ip_list;	
}

/* destroyer */
traceroute::~traceroute() {
    for(int i=0; i < MAX_TTL_DEF; i++) {
        if(array_ip_list[i].begin() == array_ip_list[i].end())
            break;
        array_ip_list[i].clear();
    }
}

ostream& operator<<(ostream& out, traceroute& t)  {
    
    list<addr> tmp[MAX_TTL_DEF];
    list<addr>::iterator p, q;
    tmp=t.getArrayList();
    
    //scan the array of list
    for(int i=0; i<MAX_TTL_DEF; i++) {
        p=tmp[i].begin();
        q=tmp[i].end();
        
        if(p->ret)
            fprintf(stdout, "IP Address: %s\n", p->ip);
        
        //scan the list
        while(p!=q) {
            
            //check if the packet has received response
            if(p->ret) {
                
                float rtt = p->time.tv_sec * 1000.0 +
                            p->time.tv_usec / 1000.0;
                fprintf(stdout, "RTT: 4.3f ", rtt);
            }
            else 
                fprintf(stdout, "* \t");
            p++;
            fprintf(stdout, "\n");
        }
    }
} 
