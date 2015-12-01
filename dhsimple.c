#include "dhuser.h"
#include "dhutils.h"
#include "dhrandom.h"
#include <stdio.h>

int main(int argc, char *argv[]) 
{
    int status = -1;
    
    dhuser_t alice, bob;
    s_memclr(&alice, sizeof(dhuser_t));
    s_memclr(&bob, sizeof(dhuser_t));

    if(argc != 2)
        goto err;

    int ac = dh_init(&alice, SERVER);    
    int bc = dh_init(&bob, CLIENT);    

    if(ac != 0 || bc != 0)
        goto err;

    int mod_len = check_size(atoi(argv[1]),0);
    if(mod_len < 0)
        goto err;

    if(dh_generateParameters(&alice, mod_len, mod_len, mod_len) < 0)
        goto err;

    if(dh_setParameters(&bob, mod_len, mod_len, mod_len, alice.P, alice.G) < 0)
        goto err;

    if(dh_generatePrivateKey(&alice) < 0 || dh_generatePrivateKey(&bob) < 0)
        goto err;

    dh_generateSharedKey(&alice); dh_generateSharedKey(&bob);

    if(dh_computeSecret(&alice, bob.Shared_E) < 0 || dh_computeSecret(&bob, alice.Shared_F) < 0)
        goto err;

    char* alice_hash = dh_computePublicHash(&alice);
    char* bob_hash = dh_computePublicHash(&bob);
    
    if(!alice_hash || !bob_hash)
        goto err;
    
    byte sig_buf[4096];
    s_memclr(sig_buf, 4096);
    unsigned int sig_len = sizeof(sig_buf);
    sign(alice_hash, sig_buf, &sig_len);
    if(verify(bob_hash, sig_buf, sig_len) != 1)
        printf("Authentication failed\n");
    else
        printf("Secret sharing successful\n");

    status = 0;
err:
    
    if(alice_hash) delete(alice_hash, strlen(alice_hash));
    if(bob_hash) delete(bob_hash, strlen(bob_hash));

    dh_destroy(&alice);
    dh_destroy(&bob);

    return status;
}
