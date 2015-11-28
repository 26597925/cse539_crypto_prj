#define _POSIX_SOURCE
#define _GNU_SOURCE
#include "dhrandom.h"
#include "dhutils.h"
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>

int check_size(unsigned int b, int type)
{
    static int lines[] = {1024,1536,2048,3072,4096,6144,8192};
    static int l = 7;

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

    /* 
     * A valid statement here would have been while(c++ < n), however for compliance with
     * https://www.securecoding.cert.org/confluence/display/c/EXP30-C.+Do+not+depend+on+the+order+of+evaluation+for+side+effects
     * we have put the increment within the loop
     */
    while(c < n) {
        getline(&line,&len,f);
        c++;
    }

    delete(line, len);
}

int generateParameters(mpz_t p, mpz_t g, unsigned int n)
{
    FILE *fp = NULL;
    int fd = 0;
    int status = -1;
    /*
     * In compliance with:
     * https://www.securecoding.cert.org/confluence/display/c/STR30-C.+Do+not+attempt+to+modify+string+literals
     * we store the string literal in a variable before passing it as an argument to RAND_load_file instead of 
     * passing it directly.
     */
    static char fn[] = "./moduli";
    
    int l = check_size(n,1);

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

    skip_lines(fp,l);

    size_t len = 0;
    char* line = NULL;

    /*
     * We getline to read data from a file as recommended 
     * https://www.securecoding.cert.org/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator
     * to allocate appropriate space for the line
     */
    if(getline(&line,&len,fp) != -1) {
       unsigned long int _g,mg;
       char mp[n+1];
       sscanf(line,"%lu %lu %s",&_g,&mg,mp);
       mpz_init_set_str(p,mp,16);
       mpz_init_set_ui(g,_g);
    }

    status = 0;

err:
    if(line) delete(line, strlen(line));

    /*
     * Closing opened file in accordance with
     * https://www.securecoding.cert.org/confluence/display/c/FIO42-C.+Close+files+when+they+are+no+longer+needed
     */
    if(fp) fclose(fp);
    if(fd > -1) close(fd);

    return status;
}

int generateRandomValue(mpz_t r, unsigned int len)
{
    int status = -1;
    unsigned int nb = len / 8;
    byte bytes[nb];
    char* ret = NULL;
    /*
     * In compliance with:
     * https://www.securecoding.cert.org/confluence/display/c/STR30-C.+Do+not+attempt+to+modify+string+literals
     * we store the string literal in a variable before passing it as an argument to RAND_load_file instead of 
     * passing it directly.
     */
    static char fn[] = "/dev/urandom";

    /*
     * Seeding the OPENSSL random generator with /dev/urandom in accordance with
     * https://www.securecoding.cert.org/confluence/display/c/MSC32-C.+Properly+seed+pseudorandom+number+generators
     * additionally, compliance with
     * https://www.securecoding.cert.org/confluence/display/c/MSC30-C.+Do+not+use+the+rand%28%29+function+for+generating+pseudorandom+numbers
     * is acheived by using the OPENSSL PRG instead of the standard library rand() function
     */
    int rc = RAND_load_file(fn,32);
    if(rc != 32) 
        goto err;
    int n = RAND_bytes(bytes,nb);
    if(n != 1)
        goto err;

    ret = bytesToHexString((uint8_t*)bytes,nb);
    mpz_init_set_str(r,ret,16);
    
    status = 0;
err:
    if(ret) delete(ret,strlen(ret));
    
    return status;
}
