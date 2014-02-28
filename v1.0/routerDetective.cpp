/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "routerDetective.h"

//Constructor of the class: sets the pointer of the array and its the last position  
routerDetective::routerDetective(list<addr>* list, int last) {
      array_list = list;
      last_position = last;
}

// Sends an ICMP echo request to each intermediate hop and receives an icmp echo reply
int routerDetective::echoReqReply(char* destAddr, uint16_t s_port) {
   
    char* payload;
    icmpManager icmp_m = icmpManager(s_port);
    int socket = icmp_m.getSocket(); //get the file descriptor which needs to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    int num_ts;
    
    fdmax = socket;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
    
    FD_SET(socket, &master);
    read_fds = master;
        
    payload = malloc(LENGTH_PAYLOAD);
    //paylod = 4 bytes equal to 0;
    memset(payload, 0, LENGTH_PAYLOAD);

    // Sends an icmp echo request
    if(!icmp_m.tpSend(payload, destAddr)) {
        cerr<<"Error: tpSend error"<<endl;
        exit(EXIT_FAILURE);
    }
        
    free(payload);
        
    if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
        cerr<<"select error\n";
        exit(EXIT_FAILURE);
    }
    
    if(FD_ISSET(socket, &read_fds)) {
        /* Receives an icmp echo response from an intermediate hop and check 
            the number of timestamps that are in the packet */
        num_ts = icmp_m.tpRecv(destAddr); 
        
        //the hop is not classifiable
        if(num_ts < 1 || num_ts > 3)
            return 0;
        //the hope is classifiable if the number of timestamps received is 1, 2 or 3
        else
            return 1;
    }
    else {
        #ifdef _DEBUG
            cout<<"Timeout expired"<<endl;
        #endif
        return -1;
    }
}

/*Sends UDP probes to classifiable hops and receives an icmp port unreach from intermediate hops*/
int routerDetective::hopsClassificability(uint16_t s_port, uint16_t dest_port, char* destAddr, char* ts_ip){
    list<addr>::iterator p;
    icmpManager icmp_m = icmpManager(s_port);
    udpRawManager* udpRawManag = new udpRawManager(s_port, dest_port); ;
    int num_ts;
    char* payload;
    int socket = icmp_m.getSocket(); //get the file descriptor which needs to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    int num_ts;
    
    fdmax = socket;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
    
    FD_SET(socket, &master);
    read_fds = master;
    
    payload = malloc(LENGTH_PAYLOAD);
    //paylod = 4 bytes equal to 0;
    memset(payload, 0, LENGTH_PAYLOAD);

    //Sends udp probe to a classifiable hop
    if(!udpRawManag.tpSend(destAddr, ts_ip, payload)) {
        cerr<<"Error: tpSend error"<<endl;
        delete udpRawManag;
        free(payload);
        return -1;
    }
    
                    
    if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
        cerr<<"select error\n";
        exit(EXIT_FAILURE);
    }
    
    free(payload);
    delete udpRawManag;
    
    if(FD_ISSET(socket, &read_fds)) {
        /* Receives an icmp echo response from an intermediate hop and check 
            the number of timestamps that are in the packet */
        num_ts = icmp_m.tpRecv(destAddr); 
        //the hop is a TP
        if(num_ts < 1)
            return 0;
        //the hop is OP
        else
            return 1;
    }
    else {
        #ifdef _DEBUG
            cout<<"Timeout expired"<<endl;
        #endif
        return -1;
    }
}

/*Coordinates the classification of hops discovered by traceroute towards the destination.
     Hops are classified as: NON CLASSIFIABLE, ON PATH or THIRD PARTY*/
bool routerDetective::thirdPartyDetection(uint16_t s_port, uint16_t dest_port, char* destAddr) {
    list<addr>::iterator p;
    //icmpManager icmp_m = icmpManager(s_port);
    int ret;
    
    //for each elements of the array that contains hops discovered by traceroute
    for(int i=1; i<= last_position; i++)
    {
        //empty list
        if(array_list[i].empty()) {
            cerr<<"Error: Empty element in the array "<<endl;
            return false;
        }
        
        for(p = array_list[i].begin(); p != array_list[i].end(); p++){
           
            /* The intermediate hop has provided a response to the traceroute
             * In the traceroute, for each hop, we sent 3 probes
             * Here we consider only one element of these */
            if(p->ret == true) {
                ret = echoReqReply(p->ip, s_port);
                 
                // Timeout expired
                 if(ret == -1)
                     return false;
                 
                 // the hope is not classifiable
                 if(ret == 0) 
                    p->classification = NON_CLASSIFIABLE;
                 
                 //the hope is classifiable
                 else {
                    ret = hopsClassificability(s_port, dest_port, destAddr, p->ip);
                    
                    //Timeout expired
                    if(ret == -1) {
                        cerr<<"Error: hopsClassificability error! "<<endl;
                        return false;
                    }
                    if(ret == 1) 
                        p->classification = ON_PATH;
                    else
                        p->classification = THIRD_PARTY;
                 }
                 break;
             }
        }
    }
    return true;
}


/* Prints the elements of the list stored */
void routerDetective::print()  {
	list<addr>* tmp;
    list<addr>::iterator p, q;
    tmp = array_list;
    int counter = 1;
    
    //scan the array of list
    for(int i = 1; i <= last_position; i++) {
        p = tmp[i].begin();

        fprintf(stdout, "%d ", counter);
        counter++;
        
        for(int j=0; j < N_PROBE_DEF; j++) {
            if(p->ret == true) {
                fprintf(stdout, "(%s) ", p->ip);
                
                if(p->classification == NON_CLASSIFIABLE)
                    fprintf(stdout, " NON CLASSIFIABLE ");
                if(p->classification == ON_PATH)
                    fprintf(stdout, " ON PATH ");
                else
                    fprintf(stdout, " THIRD PARTY ");
                break;
            }
            if(j == N_PROBE_DEF)
                fprintf(stdout, "   *    ");
            p++;
        }
        
        fprintf(stdout, "\n\n");
    }
} 
 

   
       
	
