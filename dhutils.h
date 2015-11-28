/*
 * No leading or trailing underscores in header guards in compliance with
 * https://www.securecoding.cert.org/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier
 */
#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#include <gmp.h>
#include "hexString.h"

/*
 * In accordance with 
 * https://cryptocoding.net/index.php/Coding_rules#Use_unsigned_bytes_to_represent_binary_data
 * we use unsigned char to represent bytes. This prevents cases of wrapping when dealing with bits 
 * that could lead to stomping the heap as described ion the link.
 */
typedef unsigned char byte;

void*           new(int,size_t);
void            delete(void*, size_t);
void            s_memclr(void*, size_t);
char*           hash(const char*);
void            sign(const char*, byte*, unsigned int*);
int             verify(const char*, byte*, unsigned int);
void            fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int             constantVerify(const byte*, const byte*);
int             verifySafePrime(mpz_t,int);

#endif
