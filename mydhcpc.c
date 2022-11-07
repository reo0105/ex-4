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

volatile sig_atomic_t alarm_flag = 0;
volatile sig_atomic_t hup_flag = 0;
sigset_t sigset, oldset;


/* アラームハンドラの設定 */
void alarm_handler(int sig)
{
    (void) sig;

    alarm_flag = 1;

    return;
}


/* SIGHUPハンドラの設定 */
void hup_handler(int sig)
{
    (void) sig;
    hup_flag = 1;

    return;
}


/* シグナルのセット */
void signal_set()
{
    struct sigaction sigact;

    sigemptyset(&sigact.sa_mask);

    /* SIGALRM */
    sigact.sa_handler = alarm_handler;
    sigact.sa_flags = 0;
    sigaction(SIGALRM, &sigact, NULL);

    /* SIGHUP */
    sigact.sa_handler = hup_handler;
    sigact.sa_flags = 0;
    sigaction(SIGHUP, &sigact, NULL);

    return;
}


/* シグナルのブロック */
void sig_block()
{
    sigemptyset(&sigset);

    sigaddset(&sigset, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &sigset, &oldset) < 0) {
        perror("block sigprockmask");
    }
}


/* シグナルのブロック解除 */
void sig_unblock()
{
    if (sigprocmask(SIG_SETMASK, &oldset, NULL) < 0) {
        perror("block sigprockmask");
    }
}


/* ソケットの設定 */
void set_socket(int *s)
{
    if ((*s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    return;
}


/* ソケットのクローズ */
void close_socket(int s)
{
    if (close(s) < 0) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    return;
}


/* タイマーのセット */
void set_timer()
{
    struct itimerval time;

    time.it_interval.tv_sec = 1;
    time.it_interval.tv_usec = 0;
    time.it_value.tv_sec = 1;
    time.it_value.tv_usec = 0;

    setitimer(0, &time, NULL);

    return;
}


/* イベントの解析 */
int check_event(struct dhcp_header message, struct client_status client)
{
    char str_msg_addr[INET_ADDRSTRLEN];
    char str_cli_addr[INET_ADDRSTRLEN];
    char str_msg_netmask[INET_ADDRSTRLEN];
    char str_cli_netmask[INET_ADDRSTRLEN];

    if (message.type != HEADER_TYPE_OFFER) {
        /* クライアントが存在するときはクライアントアドレス情報を文字列に変換 */
        if (inet_ntop(AF_INET, &client.addr.s_addr, str_cli_addr, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            str_cli_addr[0] = '\0';
        }

        if (inet_ntop(AF_INET, &client.netmask.s_addr, str_cli_netmask, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            str_cli_netmask[0] = '\0';
        }
    } else {
        /* そうでないときはnull */
        str_cli_addr[0] = '\0';
        str_cli_netmask[0] = '\0';
    }

    /* メッセージのアドレス情報を文字列に変換 */
    if (inet_ntop(AF_INET, &message.addr, str_msg_addr, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        str_msg_addr[0] = '\0';
    }

    if (inet_ntop(AF_INET, &message.netmask, str_msg_netmask, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        str_msg_netmask[0] = '\0';
    }

    switch(message.type) {
        case HEADER_TYPE_OFFER:
            printf("## Offer received ##\n");
            printf("type: 2(Offer), code: %d(%s), ttl: %d, addr: %s, netmask %s\n\n", message.code, (message.code == HEADER_CODE_OFFER_OK) ? "ok" : "error", ntohs(message.ttl), str_msg_addr, str_msg_netmask);
            
            /* 不正なメッセージタイプ */
            if (message.code != HEADER_CODE_OFFER_OK && message.code != HEADER_CODE_OFFER_NG) {
                fprintf(stderr, "Illegal message: code fields must be 0 or 1\n");
                return RECV_ILLEGAL_MESSAGE;
            }

            if (message.code == HEADER_CODE_OFFER_OK) {
                return RECV_OFFER_OK;
            } else {
                return RECV_OFFER_NG;
            }

        case HEADER_TYPE_ACK:
            printf("## Ack received ##\n");
            printf("type: 4(Ack), code: %d(%s), ttl: %d, addr: %s, netmask %s\n", message.code, (message.code == HEADER_CODE_ACK_OK) ? "ok" : "error", ntohs(message.ttl), str_msg_addr, str_msg_netmask);
            
            /* 不正なメッセージタイプ */
            if (message.code != HEADER_CODE_ACK_OK && message.code != HEADER_CODE_ACK_NG) {
                fprintf(stderr, "Illegal message: code fields must be 0 or 4\n");
                return RECV_ILLEGAL_MESSAGE;
            }
            
            /* メッセージに含まれるアドレスとクライアントが保持するアドレスの比較 */
            if (message.code == HEADER_CODE_ACK_NG) {
                return RECV_ACK_NG;
            } else {
                return RECV_ACK_OK;
            }
        default :
            return RECV_ILLEGAL_MESSAGE;
    }
}


/* イベントの待機 */
int wait_event(struct client_status *client, int s, struct sockaddr_in *skt, struct dhcp_header *message, int *wait_errno)
{
    ssize_t recv_size;
    socklen_t sktlen;
    sktlen = sizeof *skt;

    memset(message, 0, sizeof *message);

    /* メッセージの受信 */
    if ((recv_size = recvfrom(s, message, sizeof (struct dhcp_header), 0, (struct sockaddr *)skt, &sktlen)) < 0) {
        *wait_errno = errno;

        /* EINTR以外のエラーが発生した場合異常終了 */
        if (errno != EINTR) {
            perror("recvfrom");
            free(client);
            close_socket(s);
            exit(EXIT_FAILURE); 
        }

        return NULL_EVENT;

    } else {
        printf("recived\n");
        return check_event(*message, *client);
    }
}


/* ttlのデクリメントとタイムアウトの確認 */
void timeout_check(struct client_status *client, int *event)
{

    if (client->ttlcounter > 0) {
        client->ttlcounter = client->ttlcounter - 1;
    }

    printf("ttl = %d\n", client->ttlcounter);

    /* 状態に応じてタイムアウト後の状態へ遷移 */
    if ((client->state == WAIT_OFFER || client->state == OFFER_TIMEOUT) && client->ttlcounter == 0) {
        printf("## Offer timeout happened ##\n");
        *event = RECV_TIMEOUT;

    } else if ((client->state == WAIT_ACK || client->state == ACK_TIMEOUT) && client->ttlcounter == 0) {
        printf("## Ack timeout happened ##\n");
        *event = RECV_TIMEOUT;

    } else if ((client->state == WAIT_EXT_ACK || client->state == EXT_TIMEOUT) && client->ttlcounter == 0) {
        printf("## Ext_ack timeout happened ##\n");
        *event = RECV_TIMEOUT;

    }else if (client->state == IN_USE && client->ttlcounter <= HALF_TTL) {
        printf("## Half ttl passed ##\n");
        *event = HALF_TTL_PASSED;
    }

    return;
}


/* プログラム実行時に指定されたIP-addressのサーバーにDiscoverを送信 */
void goto_wait_offer(int s, struct client_status *client, struct sockaddr_in *skt)
{
    ssize_t send_size;
    socklen_t sktlen;
    struct dhcp_header header;

    sktlen = sizeof *skt;

    /* Discoverメッセージの作成　*/
    printf("## Discover send ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_DISCOVER;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)skt, sktlen)) < 0) {
        perror("Discover sendto");
        free(client);
        close_socket(s);
        exit(EXIT_FAILURE); 
    }

    printf("type: 1(Discover), code: %d, ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: INIT -> WAIT_OFFER --\n\n");

    /* クライアントの状態の変更 */
    client->state = WAIT_OFFER;
    client->ttlcounter = REQUEST_TTL;

    return;
}


/* offer_okを受け取った場合の処理 */
void goto_wait_ack(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) event;

    /* Request メッセージの作成*/
    printf("## Request[allocate] sent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_REQUEST;
    header.code = HEADER_CODE_REQUEST_ALLOC;
    header.ttl = htons(REQUEST_TTL);
    header.addr = message.addr;
    header.netmask = message.netmask;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("Request[allocate] sendto");
        free(client);
        close(s);
        exit(EXIT_FAILURE);
    }

    printf("type: 3(Request), code: %d(allocate), ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: %s -> WAIT_ACK --\n\n", (client->state == WAIT_OFFER) ? "WAIT_OFFER" : "OFFER_TIMEOUT");

    /* クライアントの状態の変更 */
    client->state = WAIT_ACK;
    client->ttlcounter = REQUEST_TTL;
    client->addr.s_addr = message.addr;
    client->netmask.s_addr = message.netmask;
    client->ttl = ntohs(message.ttl);

    return;
}


/* half_passedの処理　(使用期限の延長要求) */
void goto_wait_ext_ack(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) event;
    (void) message;

    /* Request メッセージの作成*/
    printf("## Request[extend] sent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_REQUEST;
    header.code = HEADER_CODE_REQUEST_EXT;
    header.ttl = htons(REQUEST_TTL);
    header.addr = client->addr.s_addr;
    header.netmask = client->netmask.s_addr;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("Request[extend] sendto");
        free(client);
        close(s);
        exit(EXIT_FAILURE);
    }

    printf("type: 3(Request), code: %d(extend), ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: IN_USE -> WAIT_EXT_ACK --\n\n");

    /* クライアントの状態の変更 */
    client->state = WAIT_EXT_ACK;
    client->ttlcounter = REQUEST_TTL;

    return;
}


/* Ack ok を受け取った場合の処理 */
void goto_in_use(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    (void) skt;
    (void) event;
    (void) s;
    (void) message;

    if (client->state == WAIT_ACK) {
        printf("-- status changed: WAIT_ACK -> IN_USE --\n\n");

    } else if (client->state == ACK_TIMEOUT) {
        printf("-- status changed: ACK_TIMEOUT -> IN_USE --\n\n");

    } else if (client->state == WAIT_EXT_ACK) {
        printf("-- status changed: WAIT_EXT_ACK -> IN_USE --\n\n");

    } else if (client->state == EXT_TIMEOUT) {
        printf("-- status changed: EXT_TIMEOUT -> IN_USE --\n\n");
    }

    /* クライアントの状態の変更 */
    client->state = IN_USE;
    client->ttlcounter = REQUEST_TTL;
    
    return;
}


/* Offerがタイムアウトした場合 */
void goto_offer_timeout(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) event;
    (void) message;

    /* Discoverの再送メッセージの作成 */
    printf("## Discover resent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_DISCOVER;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("re-Discover sendto");
        free(client);
        close(s);
        exit(EXIT_FAILURE);
    }

    printf("type: 1(Discover), code: %d, ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: WAIT_OFFER -> OFFER_TIMEOUT --\n\n");

    /* クライアントの状態の変更 */
    client->state = OFFER_TIMEOUT;
    client->ttlcounter = REQUEST_TTL;

    return;
}


/* Request[allocate]に対するAckがタイムアウトした場合の処理 */
void goto_ack_timeout(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) event;
    (void) message;

    /* Request allockの再送メッセージの作成 */
    printf("## Request[allocate] resent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_REQUEST;
    header.code = HEADER_CODE_REQUEST_ALLOC;
    header.ttl = htons(REQUEST_TTL);
    header.addr = client->addr.s_addr;
    header.netmask = client->netmask.s_addr;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("re-Request[allocate] sendto");
        free(client);
        close(s);
        exit(EXIT_FAILURE);
    }
    
    printf("type: 3(Request), code: %d(allocate), ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: WAIT_ACK -> ACK_TIMEOUT --\n\n");

    /* クライアントの状態の変更 */
    client->state = ACK_TIMEOUT;
    client->ttlcounter = REQUEST_TTL;

    return;
}


/*　Request[extend]に対するAckがタイムアウトした場合の処理 */
void goto_ext_timeout(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) event;
    (void) message;

    /* Request extの再送メッセージの作成 */
    printf("## Request[extend] resent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_REQUEST;
    header.code = HEADER_CODE_REQUEST_EXT;
    header.ttl = htons(REQUEST_TTL);
    header.addr = client->addr.s_addr;
    header.netmask = client->netmask.s_addr;

    /* sendtoがエラーならば異常終了 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("re-Request[extend] sendto");
        free(client);
        close(s);
        exit(EXIT_FAILURE);
    }

    printf("type: 3(Request), code: %d(extend), ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(client->addr), inet_ntoa(client->netmask));
    printf("-- status changed: WAIT_ACK -> EXT_TIMEOUT --\n\n");

    /* クライアントの状態の変更 */
    client->state = EXT_TIMEOUT;
    client->ttlcounter = REQUEST_TTL;

    return;
}


/* 終了状態へ向かう処理 (間違ったメッセージ[NG]　or 不正なメッセージ[Illegal] or 2度目のタイムアウト or SIGHUP を受信した場合) */
void goto_exit(struct sockaddr_in skt, struct client_status *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) message;

    if (hup_flag) {
        /* SIGHUPを受け取った場合 */
        /* Releaseメッセージの作成 */
        printf("## Release sent ##\n");
        memset(&header, 0, sizeof (struct dhcp_header));
        header.type = HEADER_TYPE_RELEASE;
        header.addr = client->addr.s_addr;

        /* sendtoがエラーならば異常終了 */
        if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
            perror("Release sendto");
            free(client);
            close(s);
            exit(EXIT_FAILURE);
        }

    /* 間違ったメッセージの場合 */
    } else if (event == RECV_OFFER_NG) {
        printf("## Recived Offer is NG ##\n");
        printf("-- status changed: %s -> EXIT --\n\n", (client->state == WAIT_OFFER) ? "WAIT_OFFER" : "OFFER_TIMEOUT");

    } else if (event == RECV_ACK_NG) {
        printf("## Recived Ack is NG ##\n");
        printf("-- status changed: %s -> EXIT --\n\n", (client->state == WAIT_ACK)     ? "WAIT_ACK" : 
                                                       (client->state == WAIT_EXT_ACK) ? "WAIT_EXT_ACK" : "ACK_TIMEOUT");

    /* 2度めのタイムアウトの場合 */
    } else if (event == RECV_TIMEOUT) {
        if (client->state == OFFER_TIMEOUT) {
            printf("## Double Offer timeout happened ##\n");

        } else if (client->state == ACK_TIMEOUT) {
            printf("## Double Ack timeout happened ##\n");

        } else if (client->state == EXT_TIMEOUT) {
            printf("## Double Ext timeout happened ##\n");
        }
    
    /* 不正なメッセージの場合 */
    } else if (event == RECV_ILLEGAL_MESSAGE) {
        printf("## Recived message is Illegal ##\n");
        printf("-- status changed: %s -> EXIT --\n\n", (client->state == WAIT_OFFER)    ? "WAIT_OFFER" : 
                                                       (client->state == OFFER_TIMEOUT) ? "OFFER_TIMEOUT" : 
                                                       (client->state == WAIT_ACK)      ? "WAIT_ACK" : 
                                                       (client->state == ACK_TIMEOUT)   ? "ACK_TIMEOUT" : 
                                                       (client->state == WAIT_EXT_ACK)  ? "WAIT_EXT_ACK" : "EXT_TIMEOUT");

    }

    /* 終了 */
    free(client);
    close(s);
    printf("EXIT Successfully\n");
    exit(EXIT_SUCCESS); // 異常終了？？
}


int main(int argc, char *argv[])
{
    int s, event, wait_errno;
    struct proctable *pt;
    struct client_status *client;
    struct dhcp_header message;
    struct sockaddr_in skt;

    if (argc != 2) {
        fprintf(stderr, "please input a IP-address\n");
        exit(EXIT_FAILURE);
    }

    signal_set();
    set_timer();
    set_socket(&s);

    mem_alloc(client, struct client_status, 1);
    if (errno != 0) {
        close_socket(s);
        exit(EXIT_FAILURE);
    }

    memset(client, 0, sizeof (struct client_status));

    /* serverのアドレスのセット */
    if (inet_aton(argv[1], &client->server_addr) != INET_SUCCESS) {
        fprintf(stderr, "input IP-address format is invalid\n");
        free(client);
        close_socket(s);
        exit(EXIT_FAILURE);
    }

    skt.sin_family = AF_INET;
    skt.sin_port = htons(MY_PORT);
    skt.sin_addr.s_addr = client->server_addr.s_addr;

    /* discoverメッセージの送信へ */
    goto_wait_offer(s, client, &skt);

    for (;;) {
        event = wait_event(client, s, &skt, &message, &wait_errno);

        /* SIGALRMに割り込まれた場合 */
        if (wait_errno == EINTR && alarm_flag) {
            //event = NULL_EVENT;
            timeout_check(client, &event);
            alarm_flag = 0;
        
        /* SIGHUPは発生した場合 */
        } else if (hup_flag) {
            printf("## SIGHUP recived ##\n");
            event = RECV_SIGHUP;
        }

        printf("state = %d, event = %d\n", client->state, event);

        /* イベントと状態に応じた処理 */
        if (event != NULL_EVENT) {
            for (pt = ptab; pt->state; pt++) {
                if (pt->state == client->state && pt->event == event) {
                    (*pt->func)(skt, client, event, s, message);
                    break;
                }
            }
            /* 該当する処理がなかった場合 */
            if (pt->state == 0) {
                fprintf(stderr, "Undefined event happened\n");
                free(client);
                close_socket(s);
                exit(EXIT_FAILURE);
            }
        }
    }

    return 0;
}