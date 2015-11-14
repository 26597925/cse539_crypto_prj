#include "dhutils.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

typedef unsigned long int gmpuint;

void dh_error(const char* msg, const char* file, int line, int e)
{
    fprintf(stderr,"In %s:%d\n",file,line);
    perror(msg);
    if(e) exit(EXIT_FAILURE);
}

void* new(int num, size_t size)
{
    void* v = calloc(num,size);
    if(!v) 
        dh_error(NULL,__FILE__,__LINE__,0);
    return v;
}

void delete(void* v)
{
    free(v);
    v = NULL;
}

char* bytesToHex(unsigned char* bytes, size_t len)
{
    size_t i;
    char* ret = new(len*2+1,sizeof(char));

    for(i = 0; i < len; i++) 
        sprintf(&ret[2*i],"%02X",bytes[i]);
    ret[len*2] = '\0';

    return ret;
}

char* hash(const char* msg)
{
    unsigned char h[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx,msg,strlen(msg));
    SHA1_Final(h,&ctx);
    return bytesToHex(h,sizeof(h));
}

void fastExponent(mpz_t r, mpz_t a, mpz_t n ,mpz_t m)
{
    mpz_t x, np;
    mpz_init(np);
    mpz_init_set(x,a);
    if(mpz_odd_p(n) > 0) {
        mpz_init_set(r,a);
    } else {
        mpz_init_set_ui(r,(gmpuint)1);
    }
    mpz_fdiv_q_ui(np,n,(gmpuint)2);

    while(mpz_cmp_ui(np,(gmpuint)0) > 0) {
        mpz_mul(x,x,x);
        mpz_mod(x,x,m);
        if(mpz_odd_p(np) > 0) {
            if(mpz_cmp_ui(r,(gmpuint)1) == 0) {
                mpz_set(r,x);
            } else {
                mpz_mul(r,r,x);
                mpz_mod(r,r,m);
            }
        }
        mpz_fdiv_q_ui(np,np,(gmpuint)2);
    }
    mpz_clear(np);
    mpz_clear(x);
}

int constantVerify(const char* a, const char* b)
{
    size_t d = strlen(a) ^ strlen(b);
    size_t i;
    for(i = 0; i < strlen(a) && i < strlen(b); i++) {
        d |= a[i] ^ b[i];
    }
    return d == 0;
}

int verifySafePrime(mpz_t p, int iter)
{
    int ret = 1;

    if(mpz_probab_prime_p(p,iter) == 0) {
        return 0;
    }

    mpz_t q,t;
    mpz_init(q);
    mpz_init(t);

    mpz_sub_ui(t,p,(gmpuint)1);

    mpz_fdiv_q_ui(q,t,(gmpuint)2);

    if(mpz_probab_prime_p(q,iter) == 0) {
        ret = 0;
    }

    mpz_clear(q);
    mpz_clear(t);

    return ret;
}

