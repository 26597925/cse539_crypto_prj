#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[])
{
    if(argc < 6) {  
        dh_error("Usage: dhclient <ip> <port> <min mod> <mod> <max mod>",__FILE__,__LINE__,1);
    }

    unsigned int minP = atoi(argv[3]);
    unsigned int iP = atoi(argv[4]);
    unsigned int maxP = atoi(argv[5]);

    unsigned char initBuf[3*sizeof(unsigned int) + 1];

    snprintf((char*)initBuf,sizeof(initBuf),"%u%u%u",minP,iP,maxP);

    dhsocket_t sock;
    
    if(dhsocket_init(&sock) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);

    printf("Socket connected\n");

    if(dhsocket_client_start(&sock,argv[1],atoi(argv[2])) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);

    printf("Serv: %d\n",sock.sfd);

    dhsocket_send(sock.sfd,initBuf,strlen((char*)initBuf));

    dhuser_t bob;

    dh_init(&bob,minP,iP,maxP,256);
    
    dh_generateSharedKey(&bob);

    char* shared = mpz_get_str(NULL,16,bob.values[SHARED]);
    dhsocket_send(sock.sfd, shared, strlen(shared));
    delete(shared);
    
    size_t bs = mpz_sizeinbase(bob.values[SHARED], 16);
    size_t hs = 64;
    size_t bufsize = bs+hs;
    unsigned char buf[bufsize+1];
    dhsocket_recv(sock.sfd, buf, bufsize);
    buf[bufsize] = '\0';

    char other[bs+1];
    char ohash[hs+1];
    char typespec[7];
    snprintf(typespec,sizeof(typespec),"%%%zds%%%zds",bs,hs);
    sscanf((char*)buf,typespec,other,ohash);

    mpz_t o;
    mpz_init_set_str(o,other,16);
    dh_computeSecret(&bob,o);
    mpz_clear(o);

    char* hash = dh_computePublicHash(&bob,1);
    
    if(constantVerify(hash,ohash) != 0)
        dh_error("Authentication Failed",__FILE__,__LINE__,0);
    else
        gmp_printf("Secret:\n%Zx\n",bob.values[SECRET]);

    dh_destroy(&bob);

    dhsocket_close(&sock);

    return 0;
}
