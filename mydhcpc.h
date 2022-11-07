#ifndef MYDHCPC
    #define MYDHCPC

#include <netinet/in.h>
#include <signal.h>
#include "mydhcp.h"

#define REQUEST_TTL 20
#define HALF_TTL (REQUEST_TTL / 2)
// #define LINE_SIZE 128
// #define MAX_IPS 10

extern volatile sig_atomic_t hup_flag;

enum cstate {
    INIT = 1,
    WAIT_OFFER,
    WAIT_ACK,
    IN_USE,
    WAIT_EXT_ACK,
    OFFER_TIMEOUT,
    ACK_TIMEOUT,
    EXT_TIMEOUT,
    EXIT
};

enum cevent {
    //EXEC_PROGRAM = 1,
    RECV_OFFER_OK = 1,
    RECV_OFFER_NG,
    RECV_ACK_OK,
    RECV_ACK_NG,
    HALF_TTL_PASSED,
    RECV_TIMEOUT,
    RECV_ILLEGAL_MESSAGE,
    RECV_SIGHUP,
    NULL_EVENT
};

struct client_status {
    int state;         
    int ttlcounter;    
    int sock; // クライアントが使用するソケット
    struct in_addr server_addr; // サーバのIPアドレス //ネットワークオーダー
    struct in_addr addr; // 割り当てられたIPアドレス //ネットワークオーダー
    struct in_addr netmask; // 割り当てられたIPアドレスのネットマスク //ネットワークオーダー
    uint16_t ttl; // IPアドレスの使用期限 //ホストバイトオーダー
};


// void timeout(int sig);
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <ctype.h>

#include "mydhcpc.h"
#include "mydhcp.h"
#include "util.h"

// signalのブロックとかはどうなる？？

void alarm_handler(int);
void hup_handler(int);
void signal_set();
void set_socket(int *);
void close_socket(int );
void set_timer();
int check_event(struct dhcp_header, struct client_status);
int wait_event(struct client_status *, int, struct sockaddr_in *, struct dhcp_header *, int *);
void timeout_check(struct client_status *, int *);
void goto_wait_offer(int, struct client_status *, struct sockaddr_in *);
void goto_wait_ack(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);
void goto_wait_ext_ack(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);
void goto_in_use(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);
void goto_offer_timeout(struct sockaddr_in, struct client_status *, int , int , struct dhcp_header);
void goto_ack_timeout(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);
void goto_ext_timeout(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);
void goto_exit(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header);



// struct ip {
//     struct ip *fp;
//     struct ip *bp;
//     struct in_addr addr;     // allocated IP address
//     struct in_addr netmask;  // allocated netmask
// };

// struct ip *ip_head;

struct proctable {
    int state;
    int event;
    void (*func)(struct sockaddr_in, struct client_status *, int, int, struct dhcp_header); //sstate, state *
}  ptab[] = {
    //{INIT,          EXEC_PROGRAM,         goto_wait_offer}, //initっていう状態の実行は初期状態で行うからいらない
    {WAIT_OFFER,    RECV_OFFER_OK,        goto_wait_ack}, //
    {WAIT_OFFER,    RECV_OFFER_NG,        goto_exit},
    {WAIT_OFFER,    RECV_ILLEGAL_MESSAGE, goto_exit},
    {WAIT_OFFER,    RECV_TIMEOUT,         goto_offer_timeout}, //
    {WAIT_ACK,      RECV_ACK_OK,          goto_in_use}, //
    {WAIT_ACK,      RECV_TIMEOUT,         goto_ack_timeout}, //
    {WAIT_ACK,      RECV_ACK_NG,          goto_exit},
    {WAIT_ACK,      RECV_ILLEGAL_MESSAGE, goto_exit},
    {IN_USE,        HALF_TTL_PASSED,      goto_wait_ext_ack},
    {IN_USE,        RECV_SIGHUP,          goto_exit}, //シグナルハンドラでやるからいらない？
    {WAIT_EXT_ACK,  RECV_ACK_OK,          goto_in_use}, //
    {WAIT_EXT_ACK,  RECV_TIMEOUT,         goto_ext_timeout}, // 
    {WAIT_EXT_ACK,  RECV_ACK_NG,          goto_exit},
    {WAIT_EXT_ACK,  RECV_ILLEGAL_MESSAGE, goto_exit},
    {OFFER_TIMEOUT, RECV_OFFER_OK,        goto_wait_ack}, //
    {OFFER_TIMEOUT, RECV_OFFER_NG,        goto_exit},
    {OFFER_TIMEOUT, RECV_TIMEOUT,         goto_exit},
    {OFFER_TIMEOUT, RECV_ILLEGAL_MESSAGE, goto_exit},
    {ACK_TIMEOUT,   RECV_ACK_OK,          goto_in_use}, //
    {ACK_TIMEOUT,   RECV_ACK_NG,          goto_exit},
    {ACK_TIMEOUT,   RECV_TIMEOUT,         goto_exit},
    {ACK_TIMEOUT,   RECV_ILLEGAL_MESSAGE, goto_exit},
    {EXT_TIMEOUT,   RECV_ACK_OK,          goto_in_use}, //
    {EXT_TIMEOUT,   RECV_ACK_NG,          goto_exit},
    {EXT_TIMEOUT,   RECV_TIMEOUT,         goto_exit},
    {EXT_TIMEOUT,   RECV_ILLEGAL_MESSAGE, goto_exit},
    {0,             0,                    NULL}
};

#endif