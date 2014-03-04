#include "trace_header.h"
#include "traceroute.h"
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
