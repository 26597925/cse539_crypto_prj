/*
 * No leading or trailing underscores in header guards in compliance with
 * https://www.securecoding.cert.org/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier
 */
#ifndef DH_RANDOM_H
#define DH_RANDOM_H

#include <gmp.h>

int     check_size(unsigned int, int);
int     generateParameters(mpz_t,mpz_t,unsigned int);
int     generateRandomValue(mpz_t,unsigned int);

#endif
