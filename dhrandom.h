#ifndef DH_RANDOM_H
#define DH_RANDOM_H

#include <gmp.h>

int     check_size(unsigned int,int);
int     generateParameters(mpz_t,mpz_t,unsigned int);
int     generateRandomValue(mpz_t,unsigned int);

#endif
