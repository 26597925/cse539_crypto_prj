#ifndef DHUSER_H
#define DHUSER_H

#include <gmp.h>

#define SERVER 0
#define CLIENT 1

struct dhuser
{
    int role;
    const char* server_id;
    const char* client_id;
    unsigned int min_mod_size;
    unsigned int mod_size;
    unsigned int max_mod_size;
    mpz_t P;
    mpz_t G;
    mpz_t X;
    mpz_t Shared_E;
    mpz_t Shared_F;
    mpz_t K;
};
typedef struct dhuser dhuser_t;

int             dh_init(dhuser_t*, int);
int             dh_generateParameters(dhuser_t*, unsigned int, unsigned int, unsigned int);
int             dh_setParameters(dhuser_t*, unsigned int, unsigned int, unsigned int, const char*, const char*);
int             dh_generatePrivateKey(dhuser_t*);
void            dh_generateSharedKey(dhuser_t*);
int             dh_computeSecret(dhuser_t*, mpz_t);
char*           dh_computePublicHash(dhuser_t*);
void            dh_destroy(dhuser_t*);

#endif
