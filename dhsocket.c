#include <string.h>
#include <stdio.h>
#include "dhsocket.h"
#include "dhutils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int dhsocket_init(dhsocket_t* this)
{
    this->cfd = 0;
    this->sfd = socket(AF_INET, SOCK_STREAM, 0);
    return (this->sfd < 0);
}

int dhsocket_serv_start(dhsocket_t* this, unsigned int port)
{
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = htonl(INADDR_ANY)
        },
        .sin_port = htons(port)
    };

    bind(this->sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    return listen(this->sfd, 0) >= 0;
}

void dhsocket_serv_accept(dhsocket_t* this)
{
    this->cfd = accept(this->sfd, NULL, NULL);
}

int dhsocket_client_start(dhsocket_t* this, const char* addr, unsigned int port)
{
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = inet_addr(addr)
        },
        .sin_port = htons(port)
    };

    return connect(this->sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) >= 0;
}

void dhsocket_send(int sfd, msg_codes code, void* buf, unsigned int size)
{
    dhpacket_t *p = new(1,sizeof(dhpacket_t)+size);
    if(!p)
        return;
    p->code = code;
    memcpy(p->data, buf, size);
    send(sfd, p, sizeof(dhpacket_t)+size, 0);
    delete((void**)&p);
}

void dhsocket_recv(int sfd, void* buf, unsigned int size)
{
    dhpacket_t *p = new(1,sizeof(dhpacket_t)+size);
    if(!p)
        return;
    recv(sfd, p, sizeof(dhpacket_t)+size, 0);
    memcpy(buf,p->data,size);
    delete((void**)&p);
}

void dhsocket_close(dhsocket_t* this)
{
    shutdown(this->sfd,SHUT_WR);
    close(this->sfd);
}
