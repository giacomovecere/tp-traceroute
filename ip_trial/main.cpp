#include "udp.h"
#include "trace_header.h"
#include "ip.h"

int main() {
    
    udpRawManager urm = new udpRawManager(3333, 44444);
    char* dest = "90.147.81.177";
    urm.send(dest, dest);
    
}
