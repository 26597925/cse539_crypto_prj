#ifndef DHUSER_H
#define DHUSER_H

#include <gmp.h>

#define MIN_MOD_LEN 0
#define I_MOD_LEN 1
#define MAX_MOD_LEN 2
#define PRIME_MODULUS 3
#define GENERATOR 4
#define SHARED 5
#define OTHER 6 
#define SECRET 7
#define PRIVATE 8

struct dhuser
{
    mpz_t* values;
};
typedef struct dhuser dhuser_t;

void    dh_init(dhuser_t*,unsigned int, unsigned int, unsigned int, unsigned int);
void    dh_generateSharedKey(dhuser_t*);
void    dh_computeSecret(dhuser_t*, mpz_t);
char*   dh_computePublicHash(dhuser_t*,int);
void    dh_destroy(dhuser_t*);

#endif
