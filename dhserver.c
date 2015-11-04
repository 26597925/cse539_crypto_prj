#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[])
{
    if(argc < 2) {
        dh_error("Usage: dhserver <port>",__FILE__,__LINE__,1);
    }
    
    dhsocket_t sock;
    
    if(dhsocket_init(&sock) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);
    
    printf("Socket connected\n");

    if(dhsocket_serv_start(&sock,atoi(argv[1])) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);

    dhsocket_serv_accept(&sock);

    if(sock.cfd >= 0) 
        printf("Client connected on %d\n",sock.cfd);

    unsigned char buf[3*sizeof(unsigned int)+1];
    dhsocket_recv(sock.cfd, buf, sizeof(buf)-1);
    buf[sizeof(buf)] = '\0';
    unsigned char minP[sizeof(unsigned int) + 1];
    unsigned char iP[sizeof(unsigned int) + 1];
    unsigned char maxP[sizeof(unsigned int) + 1];
    sscanf((char*)buf,"%4s%4s%4s",minP,iP,maxP);

    unsigned int uminP = atoi((char*)minP);
    unsigned int uiP = atoi((char*)iP);
    unsigned int umaxP = atoi((char*)maxP);
    //printf("%u\n%u\n%u\n",uminP,uiP,umaxP);

    dhuser_t alice;

    dh_init(&alice,uminP,uiP,umaxP,256);

    dh_generateSharedKey(&alice);
   
    unsigned int bs = mpz_sizeinbase(alice.values[SHARED], 16);
    unsigned char other[bs+1];
    dhsocket_recv(sock.cfd,other,bs);
    other[bs] = '\0';
    
    mpz_t o;
    mpz_init_set_str(o,(char*)other,16);
    dh_computeSecret(&alice,o);
    mpz_clear(o);

    char* shared = mpz_get_str(NULL,16,alice.values[SHARED]);
    char* hash = dh_computePublicHash(&alice,0);
    dhsocket_send(sock.cfd, shared, strlen(shared));
    dhsocket_send(sock.cfd, hash, strlen(shared));
    delete(shared);delete(hash);

    gmp_printf("Secret:\n%Zx\n",alice.values[SECRET]);

    dh_destroy(&alice);

    dhsocket_close(&sock);

    return 0;
}
