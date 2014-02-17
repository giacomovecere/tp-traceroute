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
#define _DEBUG

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

bool change_timeval(timeval t, uint16_t checksum, 
                    list<addr>::iterator start, list<addr>::iterator end){
        addr* element;
        list<addr>::iterator p;
        
        if(start == end)
                return false;

        for(p=start; p!= end; ++p){
                *element = *p;
                if(element->checksum == checksum){
                    element->ret = true;
                    tv_sub(&element->time, &t);
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
                array[ttl].push_back(address_ttl_1);
            }
        }
        else {
			if(rec_port != 0) {
				#ifdef _DEBUG
					cout<<"Sending "<< (int)N_PROBE_DEF <<" packets to "<< rec_port <<" destination port"<<endl;
				#endif
				
				/* it send 'N_PROBE_DEF UDP packets to the destination
				 * each packet has different payload but same dest. port */
				uManager.send(ip_address, rec_port, ttl, payload++, N_PROBE_DEF, address_vector);
			
				for(int i = 0; i < N_PROBE_DEF; i++) {
					// it puts the 'addr' elements filled by the send method in the list
					array[ttl].push_back(address_vector[i]);
				}
			}
			else {/*?????*/}
		}
        
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
                
                if(type == 0) {
		    fprintf(stdout, "Checksum to find: %4x \n", received->checksum);
		    cout<<endl;
		    
                    //modify the correspondent elem in the list
                    change_timeval(received->time, received->checksum, array[ttl].begin(), array[ttl].end());
                    n_receive++;
                }
                if(type == 1) {
                    change_timeval(received->time, received->checksum, array[ttl].begin(), array[ttl].end());
                    done = true; //we need to exit from the for
                    n_receive++;
                }
                if(n_receive == N_PROBE_DEF-1) packets_in_time = false;
            }
            
            // this means time expired
            else {
                //if we did not receive any packets we need to restart the traceroute (with another dest. port)
                if(n_receive == 0) 
					return false;
                else 
					packets_in_time = false;
			}
        }
        //print the list of addr
        
	packets_in_time = true;
    }
    
    return true;   
}

list<addr> traceroute::getList() {
	
	
}
