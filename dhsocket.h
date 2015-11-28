/*
 * No leading or trailing underscores in header guards in compliance with
 * https://www.securecoding.cert.org/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier
 */
#ifndef DH_SOCKET_H
#define DH_SOCKET_H

struct dhsocket {
    int sfd;
    int cfd;
};
typedef struct dhsocket dhsocket_t;

typedef enum {
    MSG_KEY_DH_GEX_REQUEST = 0x00,
    MSG_KEX_DH_GEX_GROUP = 0x01,
    MSG_KEX_DH_GEX_INIT = 0x02,
    MSG_KEX_DH_GEX_REPLY = 0x03,
    MSG_KEX_DH_GEX_INTERIM = 0x04
}msg_codes;

struct dhpacket {
    msg_codes code;
    unsigned char data[];
};
typedef struct dhpacket dhpacket_t;

int     dhsocket_init(dhsocket_t*);
int     dhsocket_serv_start(dhsocket_t*, unsigned int);
void    dhsocket_serv_accept(dhsocket_t*);
int     dhsocket_client_start(dhsocket_t*, const char*, unsigned int);
void    dhsocket_send(int, msg_codes, void*, unsigned int);
void    dhsocket_recv(int, void*, unsigned int);
void    dhsocket_close(dhsocket_t*);

#endif
