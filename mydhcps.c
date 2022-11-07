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

#include "mydhcps.h"
#include "util.h"
#include "mydhcp.h"
#include "mydhcps_list.h"

//サーバー側がEXITする場所はちゃんと考えておけ
// signalのブロックとかはどうなる？？

struct proctable ptab[] = {
    {INIT,      RECV_DISCOVER,                  goto_wait_req},
    {WAIT_REQ,  RECV_REQUEST_ALLOC_OK,          goto_in_use},
    {WAIT_REQ,  RECV_REQUEST_ALLOC_NG,          goto_terminate},
    {WAIT_REQ,  RECV_ILLEGAL_MESSAGE,           goto_terminate},
    {WAIT_REQ,  RECV_DISCOVER,                  goto_wait_req},
    {IN_USE,    RECV_REQUEST_EXT_OK,            goto_in_use},
    {IN_USE,    RECV_ILLEGAL_MESSAGE,           goto_terminate},
    {IN_USE,    RECV_REQUEST_EXT_NG,            goto_terminate},
    {IN_USE,    RECV_RELEASE_OK_OR_TTL_TIMEOUT, goto_terminate},
    {IN_USE,    RECV_RELEASE_NG,                goto_in_use},
    {IN_USE,    RECV_REQUEST_ALLOC_OK,          goto_in_use},
    {TIMEOUT,   RECV_REQUEST_ALLOC_OK,          goto_in_use},
    {TIMEOUT,   RECV_REQUEST_ALLOC_NG,          goto_terminate},
    {TIMEOUT,   RECV_ILLEGAL_MESSAGE,           goto_terminate},
    {0,         0,                              NULL}
};


volatile sig_atomic_t alarm_flag = 0;
sigset_t sigset, oldset;


/* アラームハンドラ */
void alarm_handler(int sig)
{
    (void) sig;

    alarm_flag = 1;

    return;
}


/* シグナルのセット */
void signal_set()
{
    struct sigaction sigact;

    sigemptyset(&sigact.sa_mask);

    sigact.sa_handler = alarm_handler;
    sigact.sa_flags = 0;
    sigaction(SIGALRM, &sigact, NULL);

    return;
}

void sig_block()
{
    sigemptyset(&sigset);

    sigaddset(&sigset, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &sigset, &oldset) < 0) {
        perror("block sigprockmask");
    }
}


void sig_unblock()
{
    if (sigprocmask(SIG_SETMASK, &oldset, NULL) < 0) {
        perror("block sigprockmask");
    }
}


/*ipファイルからの読み込みと設定*/
void set_ip(int *s, FILE *file)
{
    int buf_index = 0, index = 0, ip_index = 0;
    char c, buf[LINE_SIZE], straddr[LINE_SIZE];
    struct ip *p[MAX_IPS];
    struct in_addr ipaddr;

    while (fgets(buf, LINE_SIZE, file) != NULL) {
        mem_alloc(p[ip_index], struct ip, 1);
        if (p[ip_index] == NULL) {
            close_socket(*s);
            free_ip(ip_head);
            exit(EXIT_FAILURE);
        }
        /* addrの設定 */
        while (isblank(c = buf[buf_index++]));

        buf_index--;
        while (!isblank(c = buf[buf_index++])) {
            straddr[index++] = c;
        }

        straddr[index] = '\0';

        /* アドレスを文字列からバイナリに変換できなかった場合はそれは用いない */
        if (inet_aton(straddr, &ipaddr) != INET_SUCCESS) {
            fprintf(stderr, "argument string of inet_aton() is invalid\n");
            free(p[ip_index]);
            index = 0;
            buf_index = 0;
            continue;
        }

        /* 変換できた場合は格納 */
        p[ip_index]->addr = ipaddr;

        index = 0;

        /*netmaskの設定*/
        while (isblank(c = buf[buf_index++]));

        buf_index--;
        while (!isblank(c = buf[buf_index++]) && c != '\n' && c != '\0') {
            straddr[index++] = c;
        }

        straddr[index] = '\0';

        /* アドレスを文字列からバイナリに変換できなかった場合はそれは用いない */
        if (inet_aton(straddr, &ipaddr) != INET_SUCCESS) {
            fprintf(stderr, "argument string of inet_aton() is invalid\n");
            free(p[ip_index]);
            index = 0;
            buf_index = 0;
            continue;
        }

        //inet_aton(straddr, &ipaddr); //この表記か上みたいにエラーチェックをするか

        /* 変換できた場合は格納 */
        p[ip_index]->netmask = ipaddr;

        /* ipのリストに加える */
        insert_tail_ip(ip_head, p[ip_index++]);
        buf_index = 0;
        index = 0;
    }
}


/* ソケットの設定 */
void set_socket(int *s)
{
    struct sockaddr_in myskt;
    in_port_t myport = MY_PORT;

    if ((*s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&myskt, 0, sizeof myskt);
    myskt.sin_family = AF_INET;
    myskt.sin_port = htons(myport);
    myskt.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(*s, (struct sockaddr *)&myskt, sizeof myskt) < 0) {
        perror("bind");
        close_socket(*s);
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


/* イベントの解析 */
int check_event(struct dhcp_header message, struct client *from)
{
    char str_msg_addr[INET_ADDRSTRLEN];
    char str_cli_addr[INET_ADDRSTRLEN];
    char str_msg_netmask[INET_ADDRSTRLEN];
    char str_cli_netmask[INET_ADDRSTRLEN];

    /* クライアントとメッセージのアドレス情報を文字列に変換 */
    if (inet_ntop(AF_INET, &message.addr, str_msg_addr, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        str_msg_addr[0] = '\0';
    }

    if (inet_ntop(AF_INET, &message.netmask, str_msg_netmask, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        str_msg_netmask[0] = '\0';
    }

    if (from != NULL) {
        if (inet_ntop(AF_INET, &from->addr.s_addr, str_cli_addr, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            str_cli_addr[0] = '\0';
        }
        if (inet_ntop(AF_INET, &from->netmask.s_addr, str_cli_netmask, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            str_cli_netmask[0] = '\0';
        }
    } else {
        str_cli_addr[0] = '\0';
        str_cli_netmask[0] = '\0';
    }

    switch(message.type) {
        case HEADER_TYPE_DISCOVER:
            printf("## Discover received ##\n");
            printf("type: 1(Discover), code: %d, ttl: %d, addr: %s, netmask %s\n", message.code, ntohs(message.ttl), str_msg_addr, str_msg_netmask);

            /* 不正なメッセージタイプの場合 */
            if (message.code != 0 || ntohs(message.ttl) != 0 || ntohs(message.addr) != 0 || ntohs(message.netmask) != 0) {
                fprintf(stderr, "Illegal message: except type fields should be 0\n");
                return RECV_ILLEGAL_MESSAGE;
            }

            return RECV_DISCOVER;

        case HEADER_TYPE_REQUEST:
            printf("## Request received ##\n");
            printf("type: 3(Request), code: %d(%s), ttl: %d, addr: %s, netmask %s\n", message.code, (message.code == HEADER_CODE_REQUEST_ALLOC) ? "alloc" : "extend", ntohs(message.ttl), str_msg_addr, str_msg_netmask);
            
            /* 不正なメッセージタイプの場合 */
            if (message.code != HEADER_CODE_REQUEST_ALLOC && message.code != HEADER_CODE_REQUEST_EXT) {
                fprintf(stderr, "Illegal message: code fields should be 2 or 3\n");
                return RECV_ILLEGAL_MESSAGE;
            }
            
            /* メッセージに含まれるアドレス情報とクライアントが保持するアドレス情報を比較 */
            if ((message.addr != from->addr.s_addr || message.netmask != from->netmask.s_addr)) {
                fprintf(stderr, "Address or mask is not match \nmsg_addr: %s, msg_mask: %s\ncli_addr: %s, cli_mask: %s\n", str_msg_addr, str_msg_netmask, str_cli_addr, str_cli_netmask);
                
                if (message.code == HEADER_CODE_REQUEST_ALLOC) {
                    return RECV_REQUEST_ALLOC_NG;
                } else {
                    return RECV_REQUEST_EXT_NG;
                }
            }

            /* ttlフィールドが可能範囲を超えている場合はエラー */
            if (ntohs(message.ttl) > chead->ttl) {
                fprintf(stderr, "Recived ttl field is too big\n");

                if (message.code == HEADER_CODE_REQUEST_ALLOC) {
                    return RECV_REQUEST_ALLOC_NG;
                } else {
                    return RECV_REQUEST_EXT_NG;
                }
            }

            /* 正常なメセージの場合 */
            if (message.code == HEADER_CODE_REQUEST_ALLOC) {
                return RECV_REQUEST_ALLOC_OK;
            } else {
                return RECV_REQUEST_EXT_OK;
            }

        case HEADER_TYPE_RELEASE:
            printf("## Release recived ##\n");
            printf("type: 5(Release), code: %d, ttl: %d, addr: %s, netmask %s\n", message.code, ntohs(message.ttl), str_msg_addr, str_msg_netmask);

            /* 不正なメッセージの場合 */
            if (message.code != 0 || ntohs(message.ttl) != 0 || ntohl(message.netmask) != 0) {
                fprintf(stderr, "Illegal message: except type and addr fields should be 0\n");
                return RECV_ILLEGAL_MESSAGE;
            }

            /* メッセージのアドレス情報とクライアントが保持するアドレス情報を比較 */
            if (message.addr != from->addr.s_addr) {
                fprintf(stderr, "Address is not match: msg_addr: %s, cli_addr: %s\n", str_msg_addr, str_cli_addr);
                return RECV_RELEASE_NG;
            }

            return RECV_RELEASE_OK_OR_TTL_TIMEOUT;

        default:
            return RECV_ILLEGAL_MESSAGE;
    }
}


/* イベントの待機 */
int wait_event(struct client *head, struct client **from, int s, struct sockaddr_in *skt, struct dhcp_header *message, int *wait_errno)
{
    struct client *c;
    ssize_t recv_size;
    socklen_t sktlen;

    sktlen = sizeof *skt;
    memset(message, 0, sizeof *message);

    sig_unblock();
    recv_size = recvfrom(s, message, sizeof (struct dhcp_header), 0, (struct sockaddr *)skt, &sktlen);
    sig_block();

    /* メッセージを受信 */
    if (recv_size < 0) {
        *wait_errno = errno;

        /* EINTR以外のエラーが発生した場合は異常終了 */
        if (errno != EINTR) {
            perror("recvfrom");
            close_socket(s);
            free_ip(ip_head);
            free_cli(chead);
            exit(EXIT_FAILURE);
        }

        return INTR_EVENT;

    } else {
        /* 該当するクライアントの探索 */
        for (c = head->fp; c != head; c = c->fp) {
            if ((skt->sin_addr.s_addr == c->id.s_addr) && (skt->sin_port == c->port)) {
                *from = c;
                break;
            }
        }

        if (c == head) {
            *from = NULL;
        }

        return check_event(*message, *from);
    }
}


/* ttlのデクリメントとタイムアウトチェック */
void timeout_check(struct sockaddr_in skt, int s)
{
    struct client *c;
    struct dhcp_header header;

    /* すべてのクライアントのttlをデクリメント */
    for (c = chead->fp; c != chead; c = c->fp) {
        if (c->ttlcounter > 0) {
            c->ttlcounter = c->ttlcounter - 1;
        }
    }

    printf("\nSIGALRM timeout\n");

    /* すべてのクライアントのタイムアウトをチェック */
    for (c = chead->fp; c != chead;) {
        if (c->ttlcounter == 0) {
            printf("## timeout happened <addr: %s", inet_ntoa(c->addr));
            printf(", netmask: %s> ##\n", inet_ntoa(c->netmask));
            if (c->state == WAIT_REQ) {
                goto_timeout(skt, c, RECV_TIMEOUT, s, header); 
                c = c->fp;
            } else {
                c = c->fp;
                goto_terminate(skt, c->bp, (c->bp->state == IN_USE) ? RECV_RELEASE_OK_OR_TTL_TIMEOUT : RECV_TIMEOUT, s, header);
            }
        } else {
            c = c->fp;
        }
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


/* Requestがタイムアウトした場合 */
void goto_timeout(struct sockaddr_in skt, struct client *client, int event, int s, struct dhcp_header message)
{
    struct dhcp_header header;
    ssize_t send_size;

    (void) event;
    (void) message;

    /* OFFERの再送メッセージの作成 */
    printf("## re-Offer sent ##\n");
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_OFFER;
    header.code = HEADER_CODE_OFFER_OK;
    header.ttl = htons(chead->ttl);
    header.addr = client->addr.s_addr;
    header.netmask = client->netmask.s_addr;

    /* sendtoがエラーならば該当するクライアントを削除 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("sendto");
        goto_terminate(skt, client, RECV_TIMEOUT, s, header);
        return;
    }

    printf("type: 2(Offer), code: %d(OK), ttl: %d, addr: %s", header.code, ntohs(header.ttl), inet_ntoa(client->addr));
    printf(", netmask %s\n", inet_ntoa(client->netmask));
    printf("-- status changed: WAIT_REQ -> TIMEOUT --\n\n");

    /* クライアントの状態の変更 */
    client->ttlcounter = chead->ttl;
    client->state = TIMEOUT;

    return;
}


/* Discoverを受け取ったとき */
void goto_wait_req(struct sockaddr_in skt, struct client *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct client *new_cli;
    struct ip *available_ip;
    struct dhcp_header header;

    (void) event;
    (void) message;
    
    /* クライアントの作成 */ 
    if (client != NULL && skt.sin_addr.s_addr == client->id.s_addr && skt.sin_port == client->port) {
        printf("not null\n");
        new_cli = client;
        mem_alloc(available_ip, struct ip, 1);
        /* malloc errorの場合 */
        if (available_ip == NULL) { 
            close_socket(s);
	        free_ip(ip_head);
	        free_cli(chead);
	        exit(EXIT_FAILURE);
        }
        available_ip->addr = client->addr;
        available_ip->netmask = client->netmask;
    } else {
        printf("malloc\n");
        mem_alloc(new_cli, struct client, 1);
        /* malloc errorの場合 */
        if (new_cli == NULL) { 
            close_socket(s);
	        free_ip(ip_head);
	        free_cli(chead);
	        exit(EXIT_FAILURE);
	    } else {  
            memset(new_cli, 0, sizeof (struct client));
            new_cli->state = INIT;
            insert_tail_cli(chead, new_cli);
             /* 割当可能なipがなかった場合 */
            if ((available_ip = get_ip_head(ip_head)) == NULL) {
                fprintf(stderr, "There is not available ip\n");

                /* OFFER(NG)メッセージの作成 */
                printf("## Offer(NG) sent ##\n");
                memset(&header, 0, sizeof (struct dhcp_header));
                header.type = HEADER_TYPE_OFFER;
                header.code = HEADER_CODE_OFFER_NG;

                /* sendtoがエラーでも何もしない(クライアント側はOffer待ちでタイムアウトする) */
                if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
                    perror("offer(NG) sendto");
                }

                printf("type: 2(Offer), code: %d(NG), ttl: %d, addr: %s, netmask %s\n", header.code, ntohs(header.ttl), inet_ntoa(new_cli->addr), inet_ntoa(new_cli->netmask));
                printf("-- status changed: WAIT_REQ -> TERMINATE --\n\n");

                /* クライアントの削除 */
                delete_cli(new_cli); // freeから家で変更

                return;
            }
	    }
    }
        
    /* ipが存在した場合 */
    printf("## Offer(OK) sent ##\n");

    /* Offer[OK]メッセージの作成 */
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_OFFER;
    header.code = HEADER_CODE_OFFER_OK;
    header.ttl = htons(chead->ttl);
    header.addr = available_ip->addr.s_addr;
    header.netmask = available_ip->netmask.s_addr;

    /* sendtoがエラーならば該当するクライアントを削除 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("Offer(OK) sendto");
        free(available_ip);
        goto_terminate(skt, client, event, s, header);
        return;
    }

    printf("type: 2(Offer), code: %d(OK), ttl: %d, addr: %s", header.code, ntohs(header.ttl), inet_ntoa(available_ip->addr));
    printf(", netmask %s\n", inet_ntoa(available_ip->netmask));
    printf("-- status changed: INIT -> WAIT_REQ --\n\n");

    /* クライアントの状態の変更 */
    new_cli->state = WAIT_REQ;
    new_cli->ttlcounter = chead->ttl;
    new_cli->id = skt.sin_addr;
    new_cli->port = skt.sin_port;
    new_cli->addr.s_addr = available_ip->addr.s_addr;
    new_cli->netmask.s_addr = available_ip->netmask.s_addr;

    free(available_ip);

    return;
}


/* Request[alloc/ext](OK) と Release[NG] を受け取った場合 */
void goto_in_use(struct sockaddr_in skt, struct client *client, int event, int s, struct dhcp_header message)
{
    ssize_t send_size;
    struct dhcp_header header;

    (void) message;

    /* 1.client側は接続切断したつもりになっている　2.サーバはクライアントの情報を更新しないことでタイムアウトする */
    if (event == RECV_RELEASE_NG) {
        return;  
    }

    printf("## Ack(OK) sent ##\n");
    /* Ack[OK]メッセージの作成 */
    memset(&header, 0, sizeof (struct dhcp_header));
    header.type = HEADER_TYPE_ACK;
    header.code = HEADER_CODE_ACK_OK;
    header.ttl = message.ttl;
    header.addr = client->addr.s_addr;
    header.netmask = client->netmask.s_addr;

    /* sendtoがエラーならば該当するクライアントを削除 */
    if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
        perror("Ack(OK) sendto");
        goto_terminate(skt, client, event, s, header);
        return;
    }

    printf("type: 4(Ack), code: %d(OK), ttl: %d, addr: %s", header.code, ntohs(header.ttl), inet_ntoa(client->addr));
    printf(", netmask %s\n", inet_ntoa(client->netmask));
    printf("-- status changed: %s -> IN_USE --\n\n", (client->state == WAIT_REQ) ? "WAIT_REQ" : 
                                                     (client->state == IN_USE)   ? "IN_USE" : "TIMEOUT");

    /* クライアントの状態の変更 */
    client->state = IN_USE;
    client->ttlcounter = ntohs(header.ttl);

    return;
}


/* 終了状態へ向かう処理 (間違ったメッセージ[NG]　or 不正なメッセージ[Illegal] or 2度目のタイムアウト or Release を受信した場合) */
void goto_terminate(struct sockaddr_in skt, struct client *client, int event, int s, struct dhcp_header message)
{
    struct ip *p;
    struct dhcp_header header;
    ssize_t send_size;

    (void) message;

    mem_alloc(p, struct ip, 1);
    if (p == NULL) {
        close_socket(s);
        free_ip(ip_head);
        free_cli(chead);
        exit(EXIT_FAILURE);
    }
    
    /* 割り当てたipの回収 */
    p->addr = client->addr;
    p->netmask = client->netmask;
    insert_tail_ip(ip_head, p);

    /* TIMEOUTかReleaseの場合 */
    if (event == RECV_RELEASE_OK_OR_TTL_TIMEOUT || event == RECV_TIMEOUT) {
        printf("-- Relase done: addr: %s", inet_ntoa(client->addr));
        printf(", netmask %s --\n", inet_ntoa(client->netmask));
        printf("-- status changed: %s -> TERMINATE --\n", (client->state == IN_USE) ? "IN_USE" : "TIMEOUT");

    /* 間違ったメッセージを受信した場合 */
    } else if (event == RECV_REQUEST_ALLOC_NG || event == RECV_REQUEST_EXT_NG) {
        printf("\n## Ack(NG) sent ##\n");
        memset(&header, 0, sizeof (struct dhcp_header));
        header.type = HEADER_TYPE_ACK;
        header.code = HEADER_CODE_ACK_NG;

        /* sendtoがエラー　1.クライアントはAck待ちでタイムアウト 2.サーバー側は通常通りクライアントを削除 */
        if ((send_size = sendto(s, &header, sizeof (struct dhcp_header), 0, (struct sockaddr *)&skt, sizeof skt)) < 0) {
            perror("Ack(NG) sendto");
            return;
        }
        
        printf("type: 4(Ack), code: %d(NG), ttl: %d, addr: %s", header.code, ntohs(header.ttl), inet_ntoa(client->addr));
        printf(", netmask %s\n", inet_ntoa(client->netmask));
        printf("-- status changed: %s -> TERMINATE --\n", (event == RECV_REQUEST_ALLOC_NG) ? "WAIT_REQ" : "IN_USE");

    /* 不正なメッセージを受信した場合 */
    } else if (event == RECV_ILLEGAL_MESSAGE) {
        printf("-- status changed: %s -> TERMINATE --\n", (client->state == WAIT_REQ) ? "WAIT_REQ" :
                                                          (client->state == IN_USE)   ? "IN_USE"   : "TIMEOUT");
    }

    /* クライアントの削除 */
    delete_cli(client);
    
    return;

}


int main(int argc, char *argv[])
{
    struct proctable *pt;
    struct client *client = NULL;
    int s, event, wait_errno;
    char c[LINE_SIZE], *end;
    FILE *config;

    struct sockaddr_in skt;
    struct dhcp_header message;

    if (argc != 2) {
        fprintf(stderr, "please input a config-file\n");
        exit(EXIT_FAILURE);
    }

    /* シグナル・タイマーのセットとソケットの準備 */
    signal_set();
    set_timer();
    set_socket(&s);

    /* ip_headのマロック */
    mem_alloc(ip_head, struct ip, 1);
    if (ip_head == NULL) {
        close_socket(s);
        exit(EXIT_FAILURE);
    }
    ip_head->fp= ip_head->bp = ip_head;

    /* ファイルのオープン */
    file_fopen(config, argv[1], "r");
    if (config == NULL) {
        close_socket(s);
        free(ip_head);
        exit(EXIT_FAILURE);
    }

    /* ファイルが空の場合 */
    if (fgets(c, LINE_SIZE, config) == NULL) {
        fprintf(stderr, "Illegal format of %s", argv[1]);
        close_socket(s);
        free(ip_head);
        exit(EXIT_FAILURE);
    }

    c[strlen(c) - 1] = '\0';

    /* ipリストの作成 */
    set_ip(&s, config);

    mem_alloc(chead, struct client, 1);
    mem_alloc(client, struct client, 1);
    /* malloc errorの場合 */
    if (chead == NULL || client == NULL) {
        close_socket(s);
        free_ip(ip_head);
        exit(EXIT_FAILURE);
    }

    chead->fp= chead->bp = chead;
    /* 641行目で完成したcの入れる(秒数)をcheadに設定 */
    chead->ttl = (uint16_t)strtol(c, &end, 10);
    /* 1行目が自然数でなかった場合 */
    if (*end != '\0') {
        fprintf(stderr, "Please check usage and input correctly.\n");
        close_socket(s);
        free(ip_head);
        exit(EXIT_FAILURE);
    }

    for (;;) {
        event = wait_event(chead, &client, s, &skt, &message, &wait_errno);

        if (wait_errno == EINTR && alarm_flag) {
            //event = NULL_EVENT;
            timeout_check(skt, s);
            alarm_flag = 0;
        } 
        if (client != NULL) printf("state = %d, event = %d\n", client->state, event);
        if (event != INTR_EVENT) {
            for (pt = ptab; pt->state; pt++) {
                if ((client != NULL && pt->state == client->state && pt->event == event) || ((pt->event == event) && (event == RECV_DISCOVER))) {
                    (*pt->func)(skt, client, event, s, message);
                    break;
                }
            }
            /* 該当する処理がなかった場合 */
            if (pt->state == 0) {
                //printf("state = %d, event = %d\n", client->state, event);
                fprintf(stderr, "Undefined event happened\n");
                free_ip(ip_head);
                free_cli(chead);
                close_socket(s);
                exit(EXIT_FAILURE);
            }
        }
    }

    return 0;
}
