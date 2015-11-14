#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include "dhrandom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static unsigned int check_client_key_size(unsigned int minP, unsigned int iP, unsigned int maxP)
{
    int i = check_size(iP,1);
    int m = check_size(minP,1);
    int x = check_size(maxP,1);
    return (i > 0) ? iP : (x > 0) ? maxP : (m > 0) ? minP : -1;
}

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

    unsigned int resP = check_client_key_size(uminP,uiP,umaxP);
    if(resP == -1) {
        char res[] = "Fail";
        dhsocket_send(sock.cfd,(unsigned char*)res,strlen(res));
        dhsocket_close(&sock);
        dh_error("No modulus of requested length found",__FILE__,__LINE__,1);
    }
    char res[5];
    snprintf(res,5,"%u",resP);
    dhsocket_send(sock.cfd,(unsigned char*)res,strlen(res));

    dhuser_t alice;

    if(dh_init(&alice,uminP,resP,umaxP,SERVER) < 0) {
        dh_destroy(&alice);
        dhsocket_close(&sock);
        dh_error("Error creating dhuser",__FILE__,__LINE__,1);
    }

    if(dh_generatePrivateKey(&alice) < 0) {
        dh_destroy(&alice);
        dhsocket_close(&sock);
        dh_error("Error generating private key",__FILE__,__LINE__,1);
    }

    dh_generateSharedKey(&alice);
   
    unsigned int bs = mpz_sizeinbase(alice.Shared_F, 16);
    unsigned char other[bs+1];
    dhsocket_recv(sock.cfd,other,bs);
    other[bs] = '\0';
    
    mpz_t o;
    mpz_init_set_str(o,(char*)other,16);
    if(dh_computeSecret(&alice,o) < 0) {
        dh_destroy(&alice);
        dhsocket_close(&sock);
        dh_error("Error generating secret",__FILE__,__LINE__,1);
    }
    mpz_clear(o);

    char* shared = mpz_get_str(NULL,16,alice.Shared_F);
    char* hash = dh_computePublicHash(&alice);
    dhsocket_send(sock.cfd, shared, strlen(shared));
    dhsocket_send(sock.cfd, hash, strlen(hash));
    delete(shared);delete(hash);

    gmp_printf("Secret:\n%Zx\n",alice.K);

    dh_destroy(&alice);

    dhsocket_close(&sock);

    return 0;
}
