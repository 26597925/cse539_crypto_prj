#define _GNU_SOURCE
#include "dhrandom.h"
#include "dhutils.h"
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int check_size(unsigned int b, int type)
{
    static int lines[] = {1536,2048,3072,4096,6144,8192};
    static int l = 6;

    int ret = -1;
    for(int i = 0; i < l; i++) {
        if(lines[i] == b) {
            ret = (type == 0) ? lines[i] : i;
            break;
        } else {
            if(lines[i] > b) {
                ret = (type == 0) ? lines[i] : i;
                break;
            }
        }
    }
    return (ret == -1) ? (type == 0) ? lines[l-1] : l-1  : ret;
}

static void skip_lines(FILE* f, int n)
{
    size_t len = 0;
    char* line = NULL;
    int c = 0;

    while(c++ < n) {
        getline(&line,&len,f);
    }

    delete((void**)&line);
}

int generateParameters(mpz_t p, mpz_t g, unsigned int n)
{
    FILE *fp = NULL;
    int status = -1;
    
    int l = check_size(n,1);

    fp = fopen("./moduli","r");

    if(!fp)
        goto err;

    skip_lines(fp,l);

    size_t len = 0;
    char* line = NULL;

    if(getline(&line,&len,fp) != -1) {
       unsigned long int _g,mg;
       char mp[n+1];
       sscanf(line,"%lu %lu %s",&_g,&mg,mp);
       mpz_init_set_str(p,mp,16);
       mpz_init_set_ui(g,_g);
    }

    status = 0;

err:
    if(line) delete((void**)&line);

    if(fp) fclose(fp);

    return status;
}

int generateRandomValue(mpz_t r, unsigned int len)
{
    int fd = 0;
    unsigned int nb = len / 8;
    unsigned char bytes[nb];
    char* ret = NULL;
    int status = -1;

    fd = open("/dev/urandom",O_RDONLY);
    if(fd < 0)
        goto err;

    if(read(fd,bytes,nb) != (int)nb)
        goto err;
    
    ret = bytesToHexString((uint8_t*)bytes,nb);
    mpz_init_set_str(r,ret,16);
    
    status = 0;

err:
    if(fd) close(fd);
    if(ret) delete((void**)&ret);
    
    return status;
}
