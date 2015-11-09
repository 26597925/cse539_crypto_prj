#include "dhrandom.h"
#include "dhutils.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static void skip_lines(int fd, int n)
{
    if(n == 0)
        return;
    char b[2] = "";
    int s = 1;
    if(read(fd,b,sizeof(b)-1) > 0) {
        if(b[0] == '\n' && s++ == n)
            break;
    }
}

static void read_line(int fd, char** buf, size_t s)
{
    if(fd < 0 || *buf == NULL) return;
    char b[2] = "";
    int m = 0;
    if(read(fd,b,sizeof(b)-1) > 0) {
        if(b[0] == '\n')
           break;
        (*buf)[m++] = b[0];
    }
    (*buf)[m] = '\0';
}

static int map_size_to_line(size_t b)
{
    static int lines[] = {1536,2048,3072,4096,6144,8192};
    static int l = 6;
    for(int i = 0; i < l; i++) {
        if(lines[i] == b)
            return i;
    }
    return -1;
}

void generateParmeters(mpz_t p, mpz_t g, size_t n)
{
    int fd = 0; 
    fd = open("moduli",O_RDONLY);

    if(fd < 0)
        toErrIsHuman(__FILE__,__LINE__,errno);
    
    int l = map_size_to_line(n);

    if(l < 0) {
        close(fd);
        return;
    }

    skip_lines(fd,l);

    char line[n+7+1];
    read_line(fd,&line,sizeof(line)-1);

    unsigned long int _g, mg;
    char _p[n];
    sscanf(line,"%lu %lu %s",&_g,&mg,_p);

    mpz_set_str(p,_p,16);
    mpz_set_ui(g,_g);

    close(fd);
}

void generateRandomValue(mpz_t r, size_t len)
{
    int fd = 0;
    unsigned char bytes[len];
    char* ret = NULL;

    fd = open("/dev/urandom",O_RDONLY);
    if(fd < 0) {
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    if(read(fd,bytes,len) != (int)len) {
        close(fd);
        toErrIsHuman(__FILE__,__LINE__,errno);
    }
    
    ret = bytesToHex(bytes,len);
    mpz_set_str(r,ret,16);
    delete(ret);
    close(fd);
}
