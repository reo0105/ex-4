#ifndef SERVER_LIST
    #define SERVER_LIST

#include <stdio.h>
#include "mydhcps.h"

void insert_tail_ip(struct ip *, struct ip *);
void insert_tail_cli(struct client *, struct client *);
void delete_cli(struct client *);
struct ip *get_ip_head(struct ip *);
void free_ip(struct ip *);
void free_cli(struct client *);

#endif