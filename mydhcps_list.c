#include <stdio.h>
#include <stdlib.h>
#include "mydhcps_list.h"
//#include "mydhcps.h"

void insert_tail_ip(struct ip *h, struct ip *p)  
{
    p->fp = h;
    p->bp = h->bp;
    h->bp->fp = p;
    h->bp = p;
    printf("insert tail\n");
}


void insert_tail_cli(struct client *h, struct client *p)  
{
    p->fp = h;
    p->bp = h->bp;
    h->bp->fp = p;
    h->bp = p;
    printf("cleate client\n");
}


struct ip *get_ip_head(struct ip *head)  
{
    struct ip *q;

    q = head->fp;
    head->fp = q->fp;
    q->fp->bp = head;
    if (q != head) {
        q->fp = q->bp = NULL;
        return q;
    }
    return NULL;
}


void delete_cli(struct client *del_cli)
{
    struct client *p;

    for (p = chead->fp; p != chead; p = p->fp) {
        //printf("there is client\n");
        if (p == del_cli) {
            printf("-- recall ip and client delete --\n\n");
            p->bp->fp = p->fp;
            p->fp->bp = p->bp;
            p->fp = p->bp = NULL;
            free(p);
            return;
        }
    }
}


void free_ip(struct ip *ip_head)
{
    struct ip *p, *q;

    for (p = ip_head->fp; p != ip_head; p = q) {
        q = p->fp;
        free(p);
    }

    free(ip_head);
    p = q = NULL;

    return;
}


void free_cli(struct client *chead)
{
    struct client *p, *q;

    for (p = chead->fp; p != chead; p = q) {
        q = p->fp;
        free(p);
    }

    free(chead);
    p = q = NULL;

    return;
}





