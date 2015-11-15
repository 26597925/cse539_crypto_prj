#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#include <gmp.h>
#include "hexString.h"

void*           new(int,size_t);
void            delete(void*);
char*           hash(const char*);
void            sign(const char*, unsigned char*, unsigned int*);
int             verify(const char*, unsigned char*, unsigned int);
void            fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int             constantVerify(const char*, const char*);
int             verifySafePrime(mpz_t,int);
void            dh_error(const char*,const char*,int,int);

#endif
