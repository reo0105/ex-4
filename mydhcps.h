#ifndef MYDHCPS
    #define MYDHCPS

#include <netinet/in.h>
#include <signal.h>
#include "mydhcp.h"

//#define REQUEST_WAIT 10
#define LINE_SIZE 128
#define MAX_IPS 10

enum sstate {
    INIT = 1,
    WAIT_REQ,
    IN_USE,
    TIMEOUT,
    TERMINATE
};

enum sevent {
    RECV_DISCOVER = 1,
    RECV_REQUEST_ALLOC_OK,
    RECV_REQUEST_ALLOC_NG,
    RECV_REQUEST_EXT_OK,
    RECV_REQUEST_EXT_NG,
    RECV_RELEASE_OK_OR_TTL_TIMEOUT,
    RECV_RELEASE_NG,
    RECV_TIMEOUT,
    //RECV_TIMEOUT_SECOND,
    RECV_ILLEGAL_MESSAGE,
    INTR_EVENT
};


struct client {
    struct client *fp;
    struct client *bp;
    int state;               // クライアントに対するサーバの状態
    int ttlcounter;          // start time
    struct in_addr id;       // client ID (IP address)
    struct in_addr addr;     // allocated IP address //ネットワークバイトオーダ
    struct in_addr netmask;  // allocated netmask　ネットワークバイトオーダー
    in_port_t port;          // client port number
    uint16_t ttl;            // time to live ホストバイトオーダー
};

struct client *chead;


void alarm_handler(int);
void signal_set();
void set_ip(int *, FILE *);
void set_socket(int *);
void close_socket(int);
int check_event(struct dhcp_header, struct client *);
int wait_event(struct client *, struct client **, int, struct sockaddr_in *, struct dhcp_header *, int *);
void timeout_check(struct sockaddr_in skt, int s);
void set_timer();
void goto_timeout(struct sockaddr_in, struct client *, int, int, struct dhcp_header );
void goto_wait_req(struct sockaddr_in, struct client *, int, int, struct dhcp_header);
void goto_in_use(struct sockaddr_in, struct client *, int, int, struct dhcp_header);
void goto_terminate(struct sockaddr_in, struct client *, int, int, struct dhcp_header );

// ipはマロックしている
struct ip {
    struct ip *fp;
    struct ip *bp;
    struct in_addr addr;     // allocated IP address ネットワークバイトオーダー
    struct in_addr netmask;  // allocated netmask　ネットワークバイトオーダー
};

struct ip *ip_head;

struct proctable {
    int state;
    int event;
    void (*func)(struct sockaddr_in, struct client *, int, int, struct dhcp_header); //state, event
};

#endif