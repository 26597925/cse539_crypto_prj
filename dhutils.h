/*
 * No leading or trailing underscores in header guards in compliance with
 * https://www.securecoding.cert.org/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier
 */
#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#include <gmp.h>
#include "hexString.h"

void*           new(int,size_t);
void            delete(void*, size_t);
void            s_memclr(void*, size_t);
char*           hash(const char*);
void            sign(const char*, unsigned char*, unsigned int*);
int             verify(const char*, unsigned char*, unsigned int);
void            fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int             constantVerify(const unsigned char*, const unsigned char*);
int             verifySafePrime(mpz_t,int);

#endif
