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

    s_memclr(&sock, sizeof(dhsocket_t));
    
    dhuser_t alice;

    s_memclr(&alice, sizeof(dhuser_t));

    int cc = dh_init(&alice, SERVER);
    
    int sc = dhsocket_init(&sock);
    
    if(argc != 2 || cc != 0 || sc != 0)
        goto err;
    
    if(dhsocket_serv_start(&sock,atoi(argv[1])) == 0)
        goto err;

    dhsocket_serv_accept(&sock);

    byte minnmax_buf[12];
    dhsocket_recv(sock.cfd, minnmax_buf, 12);
    byte minP[5];
    byte iP[5];
    byte maxP[5];
    sscanf((char*)minnmax_buf,"%4s%4s%4s",minP,iP,maxP);

    unsigned int uminP = atoi((char*)minP);
    unsigned int uiP = atoi((char*)iP);
    unsigned int umaxP = atoi((char*)maxP);

    unsigned int resP = check_client_key_size(uminP,uiP,umaxP);

    if(dh_generateParameters(&alice, uminP, resP, umaxP) < 0)
        goto err;

    /*
     * Converting to network byte order in accordance with
     * https://www.securecoding.cert.org/confluence/display/c/POS39-C.+Use+the+correct+byte+ordering+when+transferring+data+between+systems
     */
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

        byte pconcatg[len_send+1];
        /*
         * We always use snprintf to elimiate potential buffer overflow in compliance with
         * https://www.securecoding.cert.org/confluence/display/c/EXP33-C.+Do+not+read+uninitialized+memory
         * https://www.securecoding.cert.org/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator
         */
        snprintf((char*)pconcatg,sizeof(pconcatg),"%s%s",modulus,generator);
        dhsocket_send(sock.cfd,MSG_KEX_DH_GEX_GROUP,pconcatg,len_send+1);
    }
    
    if(dh_generatePrivateKey(&alice) < 0)
        goto err;

    dh_generateSharedKey(&alice);
 
    {
        unsigned int bs = mpz_sizeinbase(alice.Shared_F, 16);
        byte other[bs+1];
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
    byte hsign[2048];
    s_memclr(hsign, 2048);
    unsigned int hsign_len = sizeof(hsign);
    sign(hash,hsign,&hsign_len);
    byte* hhsign = (byte*)bytesToHexString((uint8_t*)hsign, hsign_len);    
    if(!hhsign) 
        goto err;

    {
        byte to_send[strlen(shared)+strlen((char*)hhsign)+1];
        snprintf((char*)to_send,sizeof(to_send),"%s%s",hhsign,shared);
        dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_REPLY, to_send, sizeof(to_send) - 1);
    }
 
    byte final_rec[5];
    dhsocket_recv(sock.cfd, final_rec, sizeof(final_rec) - 1);
    final_rec[4] = '\0';

    if(constantVerify(final_rec, (byte*)"Fail") == 1) {
        goto err;
    } else if(constantVerify(final_rec, (byte*)"Succ") == 1) {
        printf("Secret sharing succeeded\n");
    } else {
        goto err;
    }
    
    status = 0;

err:
    if(modulus) delete(modulus,strlen(modulus));
    if(generator) delete(generator,strlen(generator));
    if(shared) delete(shared,strlen(shared));
    if(hash) delete(hash,strlen(hash));
    if(hhsign) delete(hhsign,strlen((char*)hhsign));
    
    dh_destroy(&alice);
    dhsocket_close(&sock);

    return status;


}
