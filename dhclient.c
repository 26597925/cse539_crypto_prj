#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

static inline int count(int x)
{
    return floor(log10(x)) + 1;
}

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

    char res[9];
    dhsocket_recv(sock.sfd, (unsigned char*)res, sizeof(res)-1);
    res[8] = '\0';

    unsigned int  resP;
    char res_msg[5];
    sscanf(res,"%4s%u",res_msg,&resP);

    if(constantVerify(res_msg,"Fail") == 1) {
        dhsocket_close(&sock);
        dh_error("No modulus of requested length",__FILE__,__LINE__,1);
    } 
    
    if(constantVerify(res_msg,"Succ") != 1) {
        dhsocket_close(&sock);
        dh_error("Unknown message recieved",__FILE__,__LINE__,1);
    }

    dhuser_t bob;

    if(dh_init(&bob,minP,resP,maxP,CLIENT) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error creating dhuser",__FILE__,__LINE__,1);
    }

    if(dh_generatePrivateKey(&bob) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error generating private",__FILE__,__LINE__,1);
    }
    
    dh_generateSharedKey(&bob);

    char* shared = mpz_get_str(NULL,16,bob.Shared_E);
    dhsocket_send(sock.sfd, shared, strlen(shared));
    delete(shared);
    
    size_t bs = mpz_sizeinbase(bob.Shared_E, 16);
    size_t hs = 40;
    size_t bufsize = bs+hs;
    unsigned char buf[bufsize+1];
    dhsocket_recv(sock.sfd, buf, bufsize);
    buf[bufsize] = '\0';

    char other[bs+1];
    char ohash[hs+1];
    char typespec[count(bs)+count(hs)+5];
    snprintf(typespec,sizeof(typespec),"%%%zds%%%zds",bs,hs);
    sscanf((char*)buf,typespec,other,ohash);
    
    mpz_t o;
    mpz_init_set_str(o,other,16);
    if(dh_computeSecret(&bob,o) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error generating secret",__FILE__,__LINE__,1);
    }
    mpz_clear(o);

    char* hash = dh_computePublicHash(&bob);
    if(constantVerify(hash,ohash) == 0) {
        char sec_msg[] = "Fail";
        dhsocket_send(sock.sfd, (unsigned char*)sec_msg, strlen(sec_msg));
        dh_error("Authentication Failed",__FILE__,__LINE__,0);
    } else {
        char sec_msg[] = "Succ";
        dhsocket_send(sock.sfd, (unsigned char*)sec_msg, strlen(sec_msg));
        printf("Secret sharing succeeded\n");
    }
    delete(hash);

    dh_destroy(&bob);

    dhsocket_close(&sock);

    return 0;
}
