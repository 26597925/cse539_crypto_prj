#ifndef DHUSER_H
#define DHUSER_H

#include <stdlib.h>
#include <gmp.h>

typedef struct 
{
    mpz_t primeModulus;
    mpz_t generator;
    mpz_t shared;
    mpz_t other;
    mpz_t private;
    mpz_t secret;
} dhuser;

dhuser* dh_init(size_t);
void dh_generateSharedKey(dhuser*);
void dh_computeSecret(dhuser*, mpz_t);
char* dh_computePublicHash(dhuser*,int);
void dh_destroy(dhuser*);

#endif
