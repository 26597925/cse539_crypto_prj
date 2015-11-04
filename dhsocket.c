#include <string.h>
#include <stdio.h>
#include "dhsocket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int dhsocket_init(dhsocket_t* this)
{
    this->cfd = 0;
    return (this->sfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0;
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

void dhsocket_send(int sfd, void* buf, unsigned int size)
{
    send(sfd, buf, size, 0);
}

void dhsocket_recv(int sfd, unsigned char* buf, unsigned int size)
{
    recv(sfd, buf, size, 0);
}

void dhsocket_close(dhsocket_t* this)
{
    shutdown(this->sfd,SHUT_WR);
    close(this->sfd);
}
