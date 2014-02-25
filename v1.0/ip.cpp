
    //source structure initialization
    src.sin_family = AF_INET;
    src.sin_port = htons(source_port);
    
    //retrieve external ip address of the source host 
    struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    void * tmpAddrPtr = NULL;

    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family == AF_INET) { // check if it is IP4
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
        }
    }
    memcpy(&src.sin_addr, tmpAddrPtr, sizeof(in_addr));
    
    //bind the socket to the source address and port
    bind(sockfd, (sockaddr*)&src, sizeof(sockaddr)); 
    
    freeifaddrs(ifAddrStruct);