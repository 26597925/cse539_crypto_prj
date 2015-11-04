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

int main(int argc, char* argv[])
{
    if(argc < 2) {
        toErrIsHuman(__FILE__,__LINE__,EINVAL);
    }

    int sfd = 0, cfd = 0;

    struct sockaddr_in serv_addr;
 
    if((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }

    /*int enable = 1;
    if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        toErrIsHuman(__FILE__,__LINE__,errno);*/

    memset(&serv_addr,0,sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    bind(sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if(listen(sfd,10) < 0) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }

    cfd = accept(sfd, (struct sockaddr*)NULL, NULL);
    
    dhuser* alice = dh_init(32);
    
    dh_generateSharedKey(alice);

    size_t bs = mpz_sizeinbase(alice->shared, 16);
    char buf[bs+1];

    int  n = 0;
    while(n < (int)bs) {
        n = read(cfd, buf, bs);
        if(n < 0) {
            dh_destroy(alice);
            toErrIsHuman(__FILE__,__LINE__,errno);
        }
    }
    buf[bs] = '\0';

    mpz_t other;
    mpz_init_set_str(other,buf,16);

    dh_computeSecret(alice,other);

    mpz_clear(other);

    char* hash = dh_computePublicHash(alice,0);

    char* shared = mpz_get_str(NULL,16,alice->shared);

    write(cfd,shared,strlen(shared));

    write(cfd,hash,strlen(hash));

    delete(hash); delete(shared);

    close(cfd);

    close(sfd);

    sleep(1);

    gmp_printf("Secret: \n%Zx\n",alice->secret);

    dh_destroy(alice);

    return 0;
}
