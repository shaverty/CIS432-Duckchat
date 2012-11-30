#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <set>
#include "duckchat.h"
#include "raw.h"

void reqLogin(int sock, struct addrinfo* p, const char * user);
void reqJoin(int sock, struct addrinfo* p, const char * chan);
void reqSay(int sock, struct addrinfo* p, const char * text);
bool handleInput(int sock, struct addrinfo *p);
bool handleServer(int sock, struct addrinfo *p);

using namespace std;
set <char>joinedChannels;
char currChan[CHANNEL_MAX +1];

char inputbuf[64];
text *servergram;

#define TRUE 1;
#define FALSE 0;

int main(int argc, char *argv[]){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int flag;
    if (argc != 4){
        fprintf(stderr, "Usage: ./client server_socket server_port username\n");
        return 1;
    }
    char *server =  argv[1];
    char *port =    argv[2];
    char *user =    argv[3];
    if (atoi(port) < 0 || atoi(port) > 65535){
        printf("Port number must be between 0 and 65535.\n");
        return -1;
    }
    if (strlen(user) > USERNAME_MAX){
        printf("Username can not be longer than %d.\n", USERNAME_MAX);
        return -2;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if ((flag = getaddrinfo(server, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(flag));
        return 1;
    }
    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }
        break;
    }
    if (p == NULL) {
        fprintf(stderr, "talker: failed to bind socket\n");
        return 2;
    }
    reqLogin(sockfd, p, user);
    reqJoin(sockfd, p, "Common");
    
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    servergram = (text *) malloc(322);
    memset(&inputbuf, 0, 64);
    raw_mode();
    while (1)
    {
        handleInput(sockfd, p);
        handleServer(sockfd, p);
    }
    return 0;
}



void reqLogin(int sock, struct addrinfo* p, const char * user){
    struct request_login packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_LOGIN;
    strncpy(packet.req_username, user, 32);
    
    int status = sendto(sock, &packet, 36, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send login request\n");
    }
}
void reqLogout(int sock, struct addrinfo* p){
    struct request_logout packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_LOGOUT;
    free(servergram);
    int status = sendto(sock, &packet, 4, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send logout request\n");
    }
}
void reqJoin(int sock, struct addrinfo* p, const char * chan){
    struct request_join packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_JOIN;

    strncpy(packet.req_channel, chan, 32);
    joinedChannels.insert(*chan);
    strncpy(currChan, chan, CHANNEL_MAX);

    int status = sendto(sock, &packet, 36, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send join request\n");
    }
}
void reqSay(int sock, struct addrinfo* p, const char * text, const char * chan){
    if (strlen(chan)==0)
        printf("Error: You are currently not in a channel.\n");
    else{
    struct request_say packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_SAY;
 
    strncpy(packet.req_text, text, 64);
    strncpy(packet.req_channel, chan, 32);

    int status = sendto(sock, &packet, 100, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send say request\n");
    }}
    
}

void reqLeave(int sock, struct addrinfo* p, const char * chan){
    struct request_join packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_LEAVE;

    strncpy(packet.req_channel, chan, 32);
    joinedChannels.erase(*chan);
    if (strcmp(currChan, chan)==0)
        memset(&currChan, '\0', sizeof currChan);

    int status = sendto(sock, &packet, 36, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send leave request\n");
    }
}
void reqList(int sock, struct addrinfo* p){
    struct request_list packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = htonl(REQ_LIST);
    
    int status = sendto(sock, &packet, sizeof(struct request_list), 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send list request\n");
    }
}
void reqWho(int sock, struct addrinfo* p, const char * chan){
    struct request_who packet;
    memset(&packet, '\0', sizeof(packet));
    packet.req_type = REQ_WHO;
    
    strncpy(packet.req_channel, chan, 32);
    
    int status = sendto(sock, &packet, 36, 0, p->ai_addr, p->ai_addrlen);
    if(status == -1){
        fprintf(stderr, "Couldn't send who request\n");
    }
}
void reqSwitch(const char * chan){
    if (joinedChannels.count(*chan) ==1)
        strncpy(currChan, chan, CHANNEL_MAX);
    else
        printf("You have not subscribed to channel %s\n", chan);
}
bool handleInput(int sock, struct addrinfo *p){
    char input[64];
    memset (input, '\0', 64);
    //fgets(input,64,stdin);
    input[strlen(input)-1] = '\0';
    char x = getchar();
    if ((int)x!=-1) {
        if (x!='\n'&&strlen(inputbuf)<64) {
            inputbuf[strlen(inputbuf)] = x;
            printf("%c", x);
        }else if(x=='\n'){
            printf("%c", x);
            if (inputbuf[0] == '/'){
                if(strncmp(&inputbuf[1], "join ", 5)==0 && inputbuf[6]!='\0'){
                    reqJoin(sock, p, &inputbuf[6]);
                }else if(strncmp(&inputbuf[1], "leave ", 6)==0 && inputbuf[7]!='\0'){
                    reqLeave(sock, p, &inputbuf[7]);
                }else if(strncmp(&inputbuf[1], "list", 4)==0){
                    reqList(sock,p);
                }else if(strncmp(&inputbuf[1], "who ", 4)==0 && inputbuf[5]!='\0'){
                    reqWho(sock,p,&inputbuf[5]);
                }else if(strncmp(&inputbuf[1], "switch ", 7)==0 && inputbuf[8]!='\0'){
                    reqSwitch(&inputbuf[8]);
                }else if(strncmp(&inputbuf[1], "exit", 4)==0){
                    reqLogout(sock,p);
                    close(sock);
                    cooked_mode();
                    exit(0);
                }
                else
                    printf("*Unknown command\n");
            }else{
                reqSay(sock, p, inputbuf, currChan);
            }
            memset(&inputbuf, 0, 64);
        }
    }
    return 1;
}

bool handleServer(int sock, struct addrinfo *p){
    //struct sockaddr_storage fromAddr;
    //socklen_t fromAddrLen = sizeof(fromAddr);
    //int dgramsize = recvfrom(sock, servergram, 322, 0, (struct sockaddr *)&fromAddr, &fromAddrLen);
    int dgramsize = recvfrom(sock, servergram, 322, 0, (p->ai_addr), &(p->ai_addrlen));
    if (dgramsize>0){
        servergram->txt_type = ntohl(servergram->txt_type);
        for (unsigned int i =0; i<strlen(inputbuf); i++) {
            printf("\b \b");
        }
        if (servergram->txt_type==0) {
            if (dgramsize==sizeof(text_say)) {
                text_say * serversay = (text_say *) servergram;
                printf("[%s][%s]:%s\n",serversay->txt_channel, serversay->txt_username, serversay->txt_text);
            }else{
                printf("Error: Say datagram incorrect size.\n");
            }
        }else if(servergram->txt_type==1){
            text_list * serverlist = (text_list *) servergram;
            int size = 4+4+(serverlist->txt_nchannels)*32;
            if (dgramsize == size) {
                printf("Existing channels:\n");
                for(int i=0; i<serverlist->txt_nchannels; i++){
                    printf(" %s\n",serverlist->txt_channels[i].ch_channel);
                }
            }else{
                printf("Error: Channel list datagram incorrect size.\n");
            }
        }else if(servergram->txt_type==2){
            text_who * serverwho = (text_who *) servergram;
            int size = 4+4+32+(serverwho->txt_nusernames)*32;
            if (dgramsize == size) {
                printf("Existing channels:\n");
                printf("Users on channel %s\n",serverwho->txt_channel);
                for(int i=0; i<serverwho->txt_nusernames;i++){
                    printf(" %s\n",serverwho->txt_users[i].us_username);
                }
            }else{
                printf("Error: User list datagram incorrect size.\n");
            }
        }else if(servergram->txt_type==3){
            if (dgramsize==sizeof(text_error)) {
                text_error * servererror = (text_error *) servergram;
                printf("Error: %s\n",servererror->txt_error);
            }else{
                printf("Error: Error datagram incorrect size.\n");
            }
        }
        printf("%s", inputbuf);
    }
    return 0;
}




