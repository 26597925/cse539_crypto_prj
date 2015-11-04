#include "dhutils.h"
#include "dhuser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

int main(int argc, char* argv[])
{
    if(argc < 3) {
        toErrIsHuman(__FILE__,__LINE__,EINVAL);
    }

    int sfd = 0;
    
    struct sockaddr_in serv_addr;

    memset(&serv_addr,0,sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

    if((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }

    if(connect(sfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr)) < 0) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    
    dhuser* bob = dh_init(32);

    dh_generateSharedKey(bob);

    char* shared = mpz_get_str(NULL,16,bob->shared);

    write(sfd, shared, strlen(shared));

    delete(shared);

    size_t bs = mpz_sizeinbase(bob->shared, 16);
    size_t hs = 64;
    size_t bufsize = bs+hs;
    char buf[bufsize];
    memset(buf,0,bufsize);

    int n = 0;
    while(n < (int)bufsize) {
        n = read(sfd, buf, bufsize);
        if(n < 0) {
            dh_destroy(bob);
            toErrIsHuman(__FILE__,__LINE__,errno);
        }
    }
        
    size_t i, j;
    char sh[bs+1];
    char hh[hs+1];
    for(i = 0;i < bs; i++)
        sh[i] = buf[i];
    sh[i] = '\0';
    for(i = bs,j = 0; i < bs+hs; i++,j++)
        hh[j] = buf[i];
    hh[j] = '\0';

    mpz_t other;
    mpz_init_set_str(other,sh,16);
    dh_computeSecret(bob,other);
    mpz_clear(other);

    char* hash = dh_computePublicHash(bob,1);
     
    if(constantVerify(hash,hh) == 0) {
        dh_destroy(bob);
        printf("Authentication failed\n");
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    delete(hash);

    close(sfd);

    sleep(1);
    
    gmp_printf("Authenticated secret: \n%Zx\n",bob->secret);
    
    dh_destroy(bob);

    return 0;
}
