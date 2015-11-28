#include "dhuser.h"
#include "dhrandom.h"
#include "dhutils.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

int dh_init(dhuser_t* this , int role)
{
    int status = -1;
    if(role > 1)
        goto err;

    this->role = role;

    this->server_id = "SSH-2.0-1.0 Server \r \n";
    this->client_id = "SSH-2.0-1.0 Client \r \n";

    mpz_init(this->P);
    mpz_init(this->G);
    mpz_init(this->X);
    mpz_init(this->Shared_E);
    mpz_init(this->Shared_F);
    mpz_init(this->K);

    status = 0;
err:
    return status;
}

int dh_generateParameters(dhuser_t* this, unsigned int minP, 
        unsigned int aP, unsigned int maxP)
{
    int status = -1;

    if(!this)
        goto err;

    this->min_mod_size = minP;
    this->mod_size = aP;
    this->max_mod_size = maxP;

    if(generateParameters(this->P,this->G,this->mod_size) < 0)
        goto err;
 
    if(verifySafePrime(this->P,25) == 0) 
        goto err;

    status = 0;

err:
    return status;
}

int dh_setParameters(dhuser_t* this, unsigned int minP,
        unsigned int aP, unsigned int maxP,
        mpz_t mod, mpz_t gen)
{
    this->min_mod_size = minP;
    this->mod_size = aP;
    this->max_mod_size = maxP;
    
    mpz_set(this->P,mod);
    mpz_set(this->G,gen);
    
    if(verifySafePrime(this->P,25) == 0) {
        return -1;
    }
    
    return 0;
}

int dh_generatePrivateKey(dhuser_t* this)
{
    static int modsizes[] = {1024,1536,2048,3072,4096,6144,8192};
    static int prv_key_lens[] = {80,120,160,210,240,270,310};
    static int len = 6;

    int status = -1;

    int v = -1;
    for(int i = 0; i < len; i++) {
        if(modsizes[i] == this->mod_size)
            v = i;
    }

    if(v == -1) 
        goto err;

    if(generateRandomValue(this->X,prv_key_lens[v]) < 0)
        goto err;

    status = 0;

err:
    return status;
}

void dh_generateSharedKey(dhuser_t* this)
{
    if(this->role == 0) {
        fastExponent(this->Shared_F,this->G,this->X,this->P);
    } else {
        fastExponent(this->Shared_E,this->G,this->X,this->P);
    }
}

int dh_computeSecret(dhuser_t* this, mpz_t other)
{
    if(mpz_sizeinbase(other,16) > mpz_sizeinbase(this->P,16))
        return -1;

    if(this->role == 0) {
        mpz_set(this->Shared_E,other);
        fastExponent(this->K,this->Shared_E,this->X,this->P);
    } else {
        mpz_set(this->Shared_F,other);
        fastExponent(this->K,this->Shared_F,this->X,this->P);
    }

    return 0;
}

char* dh_computePublicHash(dhuser_t* this)
{
    char min[5], ap[5], max[5];
    snprintf(min,5,"%u",this->min_mod_size);
    snprintf(ap,5,"%u",this->mod_size);
    snprintf(max,5,"%u",this->max_mod_size);
    char* hval = NULL;

    char* p = mpz_get_str(NULL,10,this->P);
    char* g = mpz_get_str(NULL,10,this->G);
    char* f = mpz_get_str(NULL,10,this->Shared_F);
    char* e = mpz_get_str(NULL,10,this->Shared_E);
    char* k = mpz_get_str(NULL,10,this->K);

    if(!p || !g || !e || !f || !k)
        goto err;

    {
        size_t concat_len = strlen(min)+strlen(ap)+strlen(max)+strlen(p)+
                            strlen(g)+strlen(e)+strlen(f)+strlen(k)+
                            strlen(this->server_id)+strlen(this->client_id);
        char concat[concat_len+1];
        /*
         * We always use snprintf to elimiate potential buffer overflow in compliance with
         * https://www.securecoding.cert.org/confluence/display/c/EXP33-C.+Do+not+read+uninitialized+memory
         * https://www.securecoding.cert.org/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator
         */
        snprintf(concat,sizeof(concat),"%s%s%s%s%s%s%s%s%s%s",this->client_id,this->server_id,min,ap,max,p,g,e,f,k);

        hval = hash(concat);
    }

err:
    if(p) delete(p,strlen(p));
    if(g) delete(g,strlen(g));
    if(e) delete(e,strlen(e));
    if(f) delete(f,strlen(f));
    if(k) delete(k,strlen(k));
    
    return hval;
}

void dh_destroy(dhuser_t* this)
{
    mpz_clear(this->P);
    mpz_clear(this->G);
    mpz_clear(this->X);
    mpz_clear(this->Shared_E);
    mpz_clear(this->Shared_F);
    mpz_clear(this->K);
    this->server_id = NULL;
    this->client_id = NULL;
}
