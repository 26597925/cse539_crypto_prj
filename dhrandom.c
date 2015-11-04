#define _GNU_SOURCE
#include "dhrandom.h"
#include "dhutils.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int check_size(unsigned int b)
{
    static int lines[] = {1536,2048,3072,4096,6144,8192};
    static int l = 6;
    for(int i = 0; i < l; i++) {
        if(lines[i] == b)
            return i;
    }
    return -1;
}

static void skip_lines(FILE* f, int n)
{
    size_t len = 0;
    char* line = NULL;
    int c = 0;

    while(c++ < n) {
        getline(&line,&len,f);
    }

    delete(line);
}

int generateParameters(mpz_t p, mpz_t g, unsigned int n)
{
    FILE *fp = NULL;
    
    int l = check_size(n);

    if(l < 0) return -1;

    fp = fopen("../moduli","r");

    if(fp == NULL) return -2;

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

    delete(line);

    fclose(fp);

    return 0;
}

int generateRandomValue(mpz_t r, unsigned int len)
{
    int fd = 0;
    unsigned int nb = len / 8;
    unsigned char bytes[nb];
    char* ret = NULL;

    fd = open("/dev/urandom",O_RDONLY);
    if(fd < 0) {
        return -1;
    }
    if(read(fd,bytes,nb) != (int)nb) {
        close(fd);
        return -2;
    }
    
    ret = bytesToHex(bytes,nb);
    mpz_init_set_str(r,ret,16);
    delete(ret);
    close(fd);
    return 0;
}
