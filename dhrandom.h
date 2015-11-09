#ifndef DH_RANDOM_H
#define DH_RANDOM_H

#include <stdlib.h>
#include <gmp.h>

void generatePrameters(mpz_t,mpz_t,size_t);
void generateRandomValue(mpz_t,size_t);

#endif
