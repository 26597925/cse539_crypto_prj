#include "dhutils.h"
#include "dhuser.h"
#include "dhsocket.h"
#include "dhrandom.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
    int status = -1;
    
    dhsocket_t sock;
    
    dhuser_t alice;

    int cc = dh_init(&alice, SERVER);
    
    int sc = dhsocket_init(&sock);
    
    if(argc != 2 || cc != 0 || sc != 0)
        goto err;
    
    if(dhsocket_serv_start(&sock,atoi(argv[1])) == 0)
        goto err;

    dhsocket_serv_accept(&sock);

    unsigned char minnmax_buf[12];
    dhsocket_recv(sock.cfd, minnmax_buf, 12);
    unsigned char minP[5];
    unsigned char iP[5];
    unsigned char maxP[5];
    sscanf((char*)minnmax_buf,"%4s%4s%4s",minP,iP,maxP);

    unsigned int uminP = atoi((char*)minP);
    unsigned int uiP = atoi((char*)iP);
    unsigned int umaxP = atoi((char*)maxP);

    unsigned int resP = check_client_key_size(uminP,uiP,umaxP);

    if(dh_generateParameters(&alice, uminP, resP, umaxP) < 0)
        goto err;

    unsigned int tresP = htons(resP);
    dhsocket_send(sock.cfd,MSG_KEX_DH_GEX_INTERIM,&tresP,sizeof(unsigned int));
    
    char *modulus  = mpz_get_str(NULL,16,alice.P);
    char *generator  = mpz_get_str(NULL,16,alice.G); 
    if(!modulus || !generator)
        goto err;
    {
        unsigned int mod_len = strlen(modulus);
        unsigned int gen_len = strlen(generator);
        unsigned int len_send = mod_len+gen_len;

        unsigned char pconcatg[len_send+1];
        snprintf((char*)pconcatg,sizeof(pconcatg),"%s%s",modulus,generator);
        dhsocket_send(sock.cfd,MSG_KEX_DH_GEX_GROUP,pconcatg,len_send+1);
    }
    
    if(dh_generatePrivateKey(&alice) < 0)
        goto err;

    dh_generateSharedKey(&alice);
 
    {
        unsigned int bs = mpz_sizeinbase(alice.Shared_F, 16);
        unsigned char other[bs+1];
        dhsocket_recv(sock.cfd,other,bs);
        other[bs] = '\0';
 
        mpz_t o;
        mpz_init_set_str(o,(char*)other,16);
        int v = dh_computeSecret(&alice,o);
        mpz_clear(o);
        if(v < 0) 
            goto err;
    }

    char* shared = mpz_get_str(NULL,16,alice.Shared_F);
    char* hash = dh_computePublicHash(&alice);
    if(!shared || !hash) 
        goto err;
    unsigned char* hsign = calloc(4096, sizeof(unsigned char));
    unsigned int hsign_len = sizeof(hsign);
    sign(hash,hsign,&hsign_len);
    if(!hsign) 
        goto err;
    unsigned char* hhsign = (unsigned char*)bytesToHexString((uint8_t*)hsign, hsign_len);    
    if(!hhsign) 
        goto err;

    {
        unsigned char to_send[strlen(shared)+strlen((char*)hhsign)+1];
        snprintf((char*)to_send,sizeof(to_send),"%s%s",hhsign,shared);
        dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_REPLY, to_send, sizeof(to_send) - 1);
    }
 
    char final_rec[5];
    dhsocket_recv(sock.cfd, (unsigned char*)final_rec, sizeof(final_rec) - 1);
    final_rec[4] = '\0';

    if(constantVerify(final_rec, "Fail") == 1) {
        status = -13;
        goto err;
    } else if(constantVerify(final_rec, "Succ") == 1) {
        printf("Secret sharing succeeded\n");
    } else {
        status = -14;
        goto err;
    }
    
    status = 0;
err:
    if(modulus) delete((void**)&modulus);
    if(generator) delete((void**)&generator);
    if(shared) delete((void**)&shared);
    if(hash) delete((void**)&hash);
    if(hsign) delete((void**)&hsign);
    if(hhsign) delete((void**)&hhsign);
    
    dh_destroy(&alice);
    dhsocket_close(&sock);

    return status;
}
