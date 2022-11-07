#ifndef MYDHCP
    #define MYDHCP

#include <stdint.h>
#include <netinet/in.h>

extern volatile sig_atomic_t alarm_flag;

struct dhcp_header {
    uint8_t     type;
    uint8_t     code;
    uint16_t    ttl;
    in_addr_t   addr;
    in_addr_t   netmask;
};

#define MY_PORT 51230
#define INET_SUCCESS 1

//DHCPヘッダのType
#define HEADER_TYPE_DISCOVER  1
#define HEADER_TYPE_OFFER     2
#define HEADER_TYPE_REQUEST   3
#define HEADER_TYPE_ACK       4
#define HEADER_TYPE_RELEASE   5

//DHCPヘッダのCode
#define HEADER_CODE_OFFER_OK       0
#define HEADER_CODE_OFFER_NG       1
#define HEADER_CODE_REQUEST_ALLOC  2
#define HEADER_CODE_REQUEST_EXT    3
#define HEADER_CODE_ACK_OK         0
#define HEADER_CODE_ACK_NG         4

#endif