#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#include <gmp.h>

void* new(int,size_t);
void delete(void*);
char* bytesToHex(unsigned char*, size_t);
char* hash(const char*);
/*char* sign(const char*);
char* verify(const char*);*/
void fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int constantVerify(const char*, const char*);
int verifySafePrime(mpz_t,int);
void dh_error(const char*,const char*,int,int);

#endif
