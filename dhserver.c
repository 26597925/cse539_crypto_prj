#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include "dhrandom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

static unsigned int check_client_key_size(unsigned int minP, unsigned int iP, unsigned int maxP)
{
    int i = check_size(iP, 0);
    int m = check_size(minP, 0);
    int x = check_size(maxP, 0);
    return (i > 0) ? i : (x > 0) ? x : (m > 0) ? m : -1;
}

static inline int count(int x)
{
    return floor(log10(x)) + 1;
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

    dhuser_t alice;

    if(dh_init(&alice, SERVER) < 0) {
        dh_destroy(&alice);
        dhsocket_close(&sock);
        dh_error("Error creating dhuser",__FILE__,__LINE__,1);
    }
    
    unsigned int resP = check_client_key_size(uminP,uiP,umaxP);

    if(dh_generateParameters(&alice, uminP, resP, umaxP) < 0) {
        dh_destroy(&alice);
        dhsocket_close(&sock);
        dh_error("Error generating parameters",__FILE__,__LINE__,1);
    }

    char res[5];
    snprintf(res,sizeof(res),"%u",resP);
    dhsocket_send(sock.cfd,res,strlen(res));
    
    char *modulus  = mpz_get_str(NULL,16,alice.P);
    char *generator  = mpz_get_str(NULL,16,alice.G); 
    unsigned int mod_len = strlen(modulus);
    unsigned int gen_len = strlen(generator);
    unsigned int len_send = mod_len+gen_len;
    
    char pconcatg[len_send+1];
    snprintf(pconcatg,sizeof(pconcatg),"%s%s",modulus,generator);
    dhsocket_send(sock.cfd,(unsigned char*)pconcatg,strlen(pconcatg));
    delete(modulus);delete(generator);
    
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
    char to_send[strlen(shared)+strlen(hash) + 1];
    snprintf(to_send,sizeof(to_send),"%s%s",shared,hash);
    dhsocket_send(sock.cfd, to_send, strlen(to_send));
    delete(shared);delete(hash);
 
    char final_rec[5];
    dhsocket_recv(sock.cfd, (unsigned char*)final_rec, sizeof(final_rec) - 1);
    final_rec[4] = '\0';

    if(constantVerify(final_rec, "Fail") == 1) {
        dh_error("Secret sharing failed",__FILE__,__LINE__,0);
    } else if(constantVerify(final_rec, "Succ") == 1) {
        printf("Secret sharing succeeded\n");
    } else {
        dh_error("Unknown msg recevied",__FILE__,__LINE__,0);
    }

    dh_destroy(&alice);

    dhsocket_close(&sock);

    return 0;
}
