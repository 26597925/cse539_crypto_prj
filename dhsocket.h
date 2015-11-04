#ifndef DH_SOCKET_H
#define DH_SOCKET_H

struct dhsocket {
    int sfd;
    int cfd;
};
typedef struct dhsocket dhsocket_t;

int     dhsocket_init(dhsocket_t*);
int     dhsocket_serv_start(dhsocket_t*, unsigned int);
void    dhsocket_serv_accept(dhsocket_t*);
int     dhsocket_client_start(dhsocket_t*, const char*, unsigned int);
void    dhsocket_send(int, void*, unsigned int);
void    dhsocket_recv(int, unsigned char*, unsigned int);
void    dhsocket_close(dhsocket_t*);

#endif
