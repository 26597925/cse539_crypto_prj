#include "dhuser.h"
#include "dhrandom.h"
#include "dhutils.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int check_client_key_size(unsigned int minP, unsigned int iP, unsigned int maxP)
{
    int i = check_size(iP,1);
    int m = check_size(minP,1);
    int x = check_size(maxP,1);
    return (i > 0) ? i : (x > 0) ? x : (m > 0) ? m : -1;
}

void dh_init(dhuser_t* this ,unsigned int minP, unsigned int iP, unsigned int maxP, unsigned int prvLen)
{
    int modSize = check_client_key_size(minP,iP,maxP);

    if(modSize == -1)
        dh_error("Modulus size does not exist",__FILE__,__LINE__,1);

    this->values = calloc(9,sizeof(mpz_t));

    mpz_init_set_ui(this->values[MIN_MOD_LEN],(unsigned long int)minP);
    mpz_init_set_ui(this->values[I_MOD_LEN],(unsigned long int)iP);
    mpz_init_set_ui(this->values[MAX_MOD_LEN],(unsigned long int)maxP);

    if(generateParameters(this->values[PRIME_MODULUS],
                this->values[GENERATOR],modSize) < 0) {
        dh_destroy(this);
        dh_error("Error generating parameters",__FILE__,__LINE__,1);
    }
 
    if(verifySafePrime(this->values[PRIME_MODULUS],25) == 0) {
        dh_destroy(this);
        dh_error("Error verifying primality of modulus",__FILE__,__LINE__,1);
    }

    for(int i = SHARED; i <= SECRET; i++)
        mpz_init(this->values[i]);

    if(generateRandomValue(this->values[PRIVATE],prvLen) < 0) {
        dh_destroy(this);
        dh_error("Error generating private key",__FILE__,__LINE__,1);
    }
}

void dh_generateSharedKey(dhuser_t* this)
{
    fastExponent(this->values[SHARED],this->values[GENERATOR],
            this->values[PRIVATE],this->values[PRIME_MODULUS]);
}

void dh_computeSecret(dhuser_t* this, mpz_t other)
{
    mpz_set(this->values[OTHER],other);
    fastExponent(this->values[SECRET],this->values[OTHER],
            this->values[PRIVATE],this->values[PRIME_MODULUS]);
}

char* dh_computePublicHash(dhuser_t* this, int order)
{
    if(order > 1) {
        dh_destroy(this);
        dh_error("Incorrect value",__FILE__,__LINE__,1);
    }
    char* min = mpz_get_str(NULL,10,this->values[MIN_MOD_LEN]);
    char* ip = mpz_get_str(NULL,10,this->values[I_MOD_LEN]);
    char* max = mpz_get_str(NULL,10,this->values[MAX_MOD_LEN]);
    char* p = mpz_get_str(NULL,10,this->values[PRIME_MODULUS]);
    char* g = mpz_get_str(NULL,10,this->values[GENERATOR]);
    char *e, *f;
    if(order == 0) {
        e = mpz_get_str(NULL,10,this->values[OTHER]);
        f = mpz_get_str(NULL,10,this->values[SHARED]);
    } else {
        f = mpz_get_str(NULL,10,this->values[OTHER]);
        e = mpz_get_str(NULL,10,this->values[SHARED]);
    }
    char* k = mpz_get_str(NULL,10,this->values[SECRET]);
    if(!p || !g || !e || !f || !k || !min || !ip || !max) {
        dh_destroy(this);
        dh_error("Incorrect value",__FILE__,__LINE__,1);
    }
    char concat[strlen(min)+strlen(ip)+strlen(max)+strlen(p)+
        strlen(g)+strlen(e)+strlen(f)+strlen(k)+1];
    snprintf(concat,sizeof(concat),"%s%s%s%s%s%s%s%s",min,ip,max,p,g,e,f,k);
    delete(min);delete(ip);delete(max);delete(p);delete(g);delete(e);delete(f);delete(k);
    return sha256(concat);
}

void dh_destroy(dhuser_t* this)
{
    for(int i = MIN_MOD_LEN; i <= PRIVATE; i++)
        mpz_clear(this->values[i]);
    delete(this->values);
}
