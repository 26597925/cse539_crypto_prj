#include "dhutils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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

char* hash(const char* msg)
{
    unsigned char h[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)msg, strlen(msg), h);
    return bytesToHexString(h,sizeof(h));
}

void sign(const char* msg, unsigned char* sig_buf, unsigned int* sig_len)
{
    EVP_MD_CTX md;
    EVP_PKEY *pkey;
    FILE* fp;

    fp = fopen("private_key.pem","r");
    if(!fp)
        return;
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey) 
        return;

    EVP_SignInit(&md, EVP_sha1());
    EVP_SignUpdate(&md, msg, strlen(msg));
    if(EVP_SignFinal(&md, sig_buf, sig_len, pkey) != 1)
        return;
    
    EVP_PKEY_free(pkey);
}

int verify(const char* msg, unsigned char* sig_buf, unsigned int sig_len)
{
    EVP_MD_CTX md;
    EVP_PKEY *pkey;
    FILE* fp;
 
    fp = fopen("public_key.pem","r");
    if(!fp)
        return -1;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    EVP_VerifyInit(&md, EVP_sha1());
    EVP_VerifyUpdate(&md, msg, strlen((char*)msg));
    if(EVP_VerifyFinal(&md, sig_buf, sig_len, pkey) != 1)
        return 0;
    EVP_PKEY_free(pkey);

    return 1;
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

