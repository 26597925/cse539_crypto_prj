#include "dhuser.h"
#include "dhrandom.h"
#include "dhutils.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

dhuser* dh_init(size_t pklen)
{
    dhuser* this = new(1,sizeof(dhuser));

    if(!this) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }

    mpz_init_set_str(this->primeModulus,
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
            16);
    
    if(verifySafePrime(this->primeModulus,25) == 0) {
        dh_destroy(this);
        toErrIsHuman(__FILE__,__LINE__,errno);
    }

    mpz_init_set_str(this->generator,"2",16);

    mpz_init(this->shared);

    mpz_init(this->other);
    
    mpz_init(this->private);
    
    mpz_init(this->secret);

    generateRandomValue(this->private,pklen);

    return this;
}

void dh_generateSharedKey(dhuser* this)
{
    fastExponent(this->shared,this->generator,this->private,this->primeModulus);
}

void dh_computeSecret(dhuser* this, mpz_t other)
{
    mpz_set(this->other,other);
    fastExponent(this->secret,this->other,this->private,this->primeModulus);
}

char* dh_computePublicHash(dhuser* this, int order)
{
    if(order > 1) {
        dh_destroy(this);
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    char* p = mpz_get_str(NULL,10,this->primeModulus);
    char* g = mpz_get_str(NULL,10,this->generator);
    char *e, *f;
    if(order == 0) {
        e = mpz_get_str(NULL,10,this->other);
        f = mpz_get_str(NULL,10,this->shared);
    } else {
        f = mpz_get_str(NULL,10,this->other);
        e = mpz_get_str(NULL,10,this->shared);
    }
    char* k = mpz_get_str(NULL,10,this->secret);
    if(!p || !g || !e || !f || !k) {
        dh_destroy(this);
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    char concat[strlen(p)+strlen(g)+strlen(e)+strlen(f)+strlen(k)+1];
    snprintf(concat,sizeof(concat),"%s%s%s%s%s",p,g,e,f,k);
    delete(p);delete(g);delete(e);delete(f);delete(k);
    return sha256(concat);
}

void dh_destroy(dhuser* this)
{
    mpz_clear(this->primeModulus);
    mpz_clear(this->generator);
    mpz_clear(this->shared);
    mpz_clear(this->other);
    mpz_clear(this->private);
    mpz_clear(this->secret);
    delete(this);
}
