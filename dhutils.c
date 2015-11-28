#define _POSIX_SOURCE
#include "dhutils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

typedef unsigned long int gmpuint;

void * (*volatile memset_volatile)(void *, int, size_t) = memset;

/*
 * As per the following coding standard:
 * https://www.securecoding.cert.org/confluence/display/c/DCL30-C.+Declare+objects+with+appropriate+storage+durations
 * we ensure that all allocation is made using the new, delete functions defined here. The delete additionally ensures that
 * data is purged. Addtionally, new and delete while reserved in C++ are unreserved in C so we are also in compliance with
 * https://www.securecoding.cert.org/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier
 */
void* new(int num, size_t size)
{
    void* v = calloc(num,size);
    return v;
}

/*
 *
 * Best practices in memory management for Cryptographic coding suggest that
 * memory should be purged then freed to avoid leaking sensitive data between threads.
 * This is described in more detail in the following:
 * https://cryptocoding.net/index.php/Coding_rules#Clean_memory_of_secret_data
 * To acheive this we use the OPENSSL_cleanse function as recommended. This sets all allocated data
 * to NULL before being freed.
 *
 */
void delete(void* v, size_t n)
{
    OPENSSL_cleanse(v,n);
    free(v);
}

/*
 * Some compilers may optimize out calls to memset so a secure memset is needed in accordance with
 * https://cryptocoding.net/index.php/Coding_rules#Prevent_compiler_interference_with_security-critical_operations
 */
inline void s_memclr(void* v, size_t n)
{
    memset_volatile(v, 0, n);
}

char* hash(const char* msg)
{
    byte h[SHA_DIGEST_LENGTH];
    s_memclr(h, SHA_DIGEST_LENGTH);
    SHA1((byte*)msg, strlen(msg), h);
    return bytesToHexString(h,sizeof(h));
}

/*
 *
 * Code based on:
 * https://github.com/luvit/openssl/blob/master/openssl/demos/sign/sign.c
 *
 */
void sign(const char* msg, byte* sig_buf, unsigned int* sig_len)
{
    EVP_MD_CTX md;
    EVP_PKEY *pkey = NULL;
    FILE* fp = NULL;
    int fd = 0;
    /*
     * In compliance with:
     * https://www.securecoding.cert.org/confluence/display/c/STR30-C.+Do+not+attempt+to+modify+string+literals
     * we store the string literal in a variable before passing it as an argument to RAND_load_file instead of 
     * passing it directly.
     */
    static char fn[] = "private_key.pem";

    s_memclr(&md, sizeof(md));
    
    /*
     * In accordance with
     * https://www.securecoding.cert.org/confluence/display/c/FIO01-C.+Be+careful+using+functions+that+use+file+names+for+identification
     * and
     * https://www.securecoding.cert.org/confluence/display/c/FIO03-C.+Do+not+make+assumptions+about+fopen%28%29+and+file+creation
     * we open the file using POSIX open() as recommended and fdopen() to obtain the file pointer object to use standard I/O functions.
     * This is the recommended approach as per FIO03
     */
    fd = open(fn, O_RDONLY);
    if(fd == -1)
        goto err;
    fp = fdopen(fd,"r");
    if(!fp)
        goto err;
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    if(!pkey) 
        goto err;

    EVP_SignInit(&md, EVP_sha1());
    EVP_SignUpdate(&md, msg, strlen(msg));
    if(EVP_SignFinal(&md, sig_buf, sig_len, pkey) != 1)
        goto err; 

err:
    /*
     * Closing opened file in accordance with
     * https://www.securecoding.cert.org/confluence/display/c/FIO42-C.+Close+files+when+they+are+no+longer+needed
     */
    if(fp) fclose(fp);
    if(fd > -1) close(fd);
    if(pkey) EVP_PKEY_free(pkey);
}

/*
 *
 * Code based on:
 * https://github.com/luvit/openssl/blob/master/openssl/demos/sign/sign.c
 *
 */
int verify(const char* msg, byte* sig_buf, unsigned int sig_len)
{
    EVP_MD_CTX md;
    EVP_PKEY *pkey = NULL;
    FILE* fp = NULL;
    int fd = 0;
    int verified = 0;
    /*
     * In compliance with:
     * https://www.securecoding.cert.org/confluence/display/c/STR30-C.+Do+not+attempt+to+modify+string+literals
     * we store the string literal in a variable before passing it as an argument to RAND_load_file instead of 
     * passing it directly.
     */
    static char fn[] = "public_key.pem";

    s_memclr(&md, sizeof(md));
    
    /*
     * In accordance with
     * https://www.securecoding.cert.org/confluence/display/c/FIO01-C.+Be+careful+using+functions+that+use+file+names+for+identification
     * and
     * https://www.securecoding.cert.org/confluence/display/c/FIO03-C.+Do+not+make+assumptions+about+fopen%28%29+and+file+creation
     * we open the file using POSIX open() as recommended and fdopen() to obtain the file pointer object to use standard I/O functions.
     * This is the recommended approach as per FIO03
     */
    fd = open(fn, O_RDONLY);
    if(fd == -1)
        goto err;
 
    fp = fdopen(fd,"r");
    if(!fp)
        goto err;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    
    EVP_VerifyInit(&md, EVP_sha1());
    EVP_VerifyUpdate(&md, msg, strlen((char*)msg));
    verified = (EVP_VerifyFinal(&md, sig_buf, sig_len, pkey) == 1);

err:
    /*
     * Closing opened file in accordance with
     * https://www.securecoding.cert.org/confluence/display/c/FIO42-C.+Close+files+when+they+are+no+longer+needed
     */
    if(fp) fclose(fp);
    if(fd > -1) close(fd);
    if(pkey) EVP_PKEY_free(pkey);

    return verified;
}

/*
 *
 * Fast exponent algorithm implemented using GMP (mpz_t) primitives
 *
 */
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

/*
 *
 * Constant-time buffer compare. Buffers are treated as byte* as per:
 * https://cryptocoding.net/index.php/Coding_rules#Use_unsigned_bytes_to_represent_binary_data
 *
 */
int constantVerify(const byte* a, const byte* b)
{
    size_t la = strlen((char*)a);
    size_t lb = strlen((char*)b);
    size_t d = la ^ lb;
    size_t i;
    for(i = 0; i < la && i < lb; i++) {
        d |= a[i] ^ b[i];
    }
    return d == 0;
}

/*
 * Verify if (p-1)/2 = q where p and q are prime.
 * Miller-Rabin used in mpz_probab_prime_p
 * Returns 1, 2 depending on probability of being prime, 0 if
 * not prime. We consider > 0 to be a good enough check.
 *
 */
int verifySafePrime(mpz_t p, int iter)
{
    int ret = 0;

    if(mpz_probab_prime_p(p,iter) == 0)
        goto err;

    mpz_t q,t;
    mpz_init(q);
    mpz_init(t);

    mpz_sub_ui(t,p,(gmpuint)1);

    mpz_fdiv_q_ui(q,t,(gmpuint)2);

    if(mpz_probab_prime_p(q,iter) == 0) 
        goto err;

    ret = 1;

err:
    mpz_clear(q);
    mpz_clear(t);
    
    return ret;
}

