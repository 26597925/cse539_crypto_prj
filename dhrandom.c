#include "dhrandom.h"
#include "dhutils.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

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
