#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include <arpa/inet.h>
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

    dhsocket_t sock;
    
    if(dhsocket_init(&sock) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);

    if(dhsocket_client_start(&sock,argv[1],atoi(argv[2])) == 0)
        dh_error(NULL,__FILE__,__LINE__,1);
    
    unsigned int minP = atoi(argv[3]);
    unsigned int iP = atoi(argv[4]);
    unsigned int maxP = atoi(argv[5]);

    unsigned char initBuf[3*sizeof(unsigned int) + 1];

    snprintf((char*)initBuf,sizeof(initBuf),"%u%u%u",minP,iP,maxP);
    
    dhsocket_send(sock.sfd,MSG_KEY_DH_GEX_REQUEST,initBuf,strlen((char*)initBuf));

    unsigned int resP;
    dhsocket_recv(sock.sfd, &resP, sizeof(unsigned int));
    resP = ntohs(resP);
    
    unsigned int mod_len = resP/8*2;
    unsigned int gen_size = 1;
    char modulus[mod_len+1];
    char generator[gen_size+1];
    unsigned char mod_gen_buf[mod_len+gen_size+1];
    dhsocket_recv(sock.sfd,mod_gen_buf,sizeof(mod_gen_buf));
    char ts[count(mod_len)+count(gen_size)+5];
    snprintf(ts,sizeof(ts),"%%%us%%%us",mod_len,gen_size);
    sscanf((char*)mod_gen_buf,ts,modulus,generator);

    dhuser_t bob;

    if(dh_init(&bob, CLIENT) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error creating dhuser",__FILE__,__LINE__,1);
    }

    if(dh_setParameters(&bob, minP, resP, maxP, modulus, generator) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error setting parameters",__FILE__,__LINE__,1);
    }

    if(dh_generatePrivateKey(&bob) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error generating private",__FILE__,__LINE__,1);
    }
    
    dh_generateSharedKey(&bob);

    char* shared = mpz_get_str(NULL,16,bob.Shared_E);
    dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INIT, (unsigned char*)shared, strlen(shared));
    delete((void**)&shared);
    
    unsigned int bs = mpz_sizeinbase(bob.Shared_E, 16);
    unsigned int hs = 256;
    unsigned char buf[hs+bs+1];
    dhsocket_recv(sock.sfd, buf, hs+bs);
    buf[hs+bs] = '\0';

    unsigned char other[bs+1];
    unsigned char hhsign[hs+1];
    char typespec[count(bs)+count(hs)+5];
    snprintf(typespec,sizeof(typespec),"%%%us%%%us",hs,bs);
    sscanf((char*)buf,typespec,hhsign,other);

    unsigned char* hsign = (unsigned char*)hexStringToBytes((char*)hhsign);

    mpz_t o;
    mpz_init_set_str(o,(char*)other,16);
    if(dh_computeSecret(&bob,o) < 0) {
        dh_destroy(&bob);
        dhsocket_close(&sock);
        dh_error("Error generating secret",__FILE__,__LINE__,1);
    }
    mpz_clear(o);

    char* hash = dh_computePublicHash(&bob);
    if(verify(hash,hsign,hs/2) != 1) {
        char sec_msg[] = "Fail";
        dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (unsigned char*)sec_msg, strlen(sec_msg));
        dh_error("Authentication Failed",__FILE__,__LINE__,0);
    } else {
        char sec_msg[] = "Succ";
        dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (unsigned char*)sec_msg, strlen(sec_msg));
        printf("Secret sharing succeeded\n");
    }
    delete((void**)&hash);

    dh_destroy(&bob);

    dhsocket_close(&sock);

    return 0;
}
