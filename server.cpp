/*
 ** Sean Haverty and Elijah Newton
 Lots of help from beej's and variousl online sources, we have 10 minutes to hand this in.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>
//#include <string.h>
#include <string>
#include <set>
#include <map>
#include "duckchat.h"
#include <sstream>
#include <list>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ctime>





#define MAXBUFLEN 100
using namespace std;

class User;
class Channel;
string ipportkey(struct sockaddr_storage *their_addr);
void who(request_who *whoreq,struct sockaddr_storage *their_addr, int sockfd);
void login(request_login *logreq,struct sockaddr_storage **their_addr, int sockfd);
void logout(request_logout *logoutreq,struct sockaddr_storage *their_addr, int sockfd);
void join(request_join *joinreq,struct sockaddr_storage *their_addr, int sockfd);
void leave(request_leave *leavereq,struct sockaddr_storage *their_addr, int sockfd);
void say(request_say *sayreq,struct sockaddr_storage *their_addr, int sockfd);
void list_r(request_list *listreq,struct sockaddr_storage *their_addr, int sockfd);
void sendErrorPack(User * user, string str, int sockfd);
void subscribe(s2s_join *joinreq,struct sockaddr_storage *their_addr, int sockfd);
void s2s_sayReq(s2s_say *sayreq,struct sockaddr_storage *their_addr, int sockfd);
void s2s_leaveReq(s2s_leave *sayreq,struct sockaddr_storage *their_addr, int sockfd);
long long uniqueIdGen();
void softcheck(int signum);


string MYIPNUM;
string MYPORTNUM;

int sockfd;
bool setalarm=true;
// get sockaddr
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

class Server{
public:
    char ip[INET_ADDRSTRLEN];
    char* port;
    char* name;

    Server(char* nm, char* port_int)
    {
        name = nm;
        port = port_int;
    }
};

class User{
public:
    string name;
    struct sockaddr_storage *addrinf;
    set<Channel *> channels;
    char ip[INET_ADDRSTRLEN];
    char port[6];

    User(string username, struct sockaddr_storage *their_addr)
    {
        name = username;
        addrinf = their_addr;
        //addrinf = address;


        char s[INET_ADDRSTRLEN];
        char portchar[6];
        struct sockaddr_in *q = (struct sockaddr_in *)their_addr;
        int iport = ntohs(q->sin_port);
        string sip = inet_ntop(their_addr->ss_family, get_in_addr((struct sockaddr *)their_addr), s, sizeof s);
        sprintf(portchar,"%d",iport);
        string Result = portchar;
        Result+=':';
        Result+=sip;
        strncpy(ip,sip.c_str(),sip.length());
        strncpy(port, portchar, strlen(portchar));
    }

    ~User()
    {
        free(addrinf);
    }
};

class Channel{
public:
    string name;
    set<User *> users;
    map<Server*, bool> servers;

    Channel(string chanName)
    {
        name = chanName;
    }

};


map<string, User*> users;
map<string, Channel*> channels;
map<string, Server*> servers;
list<long long> uniqueid;

bool UserInChan(User *user, Channel *chan)
{
    set<User *>::iterator itr;
    itr = chan->users.find(user);

    if(itr == chan->users.end())
        return false;
    else
        return true;
}

void softJoin(int signum) {
    
    for (map<string, Channel *>::iterator itr = channels.begin(); itr!=channels.end(); ++itr )
    {
        
        for (map<Server*,bool>::iterator iter=(*itr).second->servers.begin(); iter !=(*itr).second->servers.end(); iter++)
        {
                struct addrinfo hints, *servinfo;
            
                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_INET; // set to AF_INET to force IPv4
                hints.ai_socktype = SOCK_DGRAM;
            
                getaddrinfo((*iter).first->ip, (*iter).first->port, &hints, &servinfo);
            
                struct s2s_join packet;
                memset(&packet, '\0', sizeof(packet));
                packet.req_type = REQ_S2S_JOIN;
                strncpy(packet.req_channel, (*itr).second->name.c_str(), 32);
            
                cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<(*iter).first->ip<<":"<<(*iter).first->port<<" send S2S Join " << packet.req_channel << endl;

                sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
        }
    }
    if (setalarm){
        signal(SIGALRM, softcheck);
        alarm(60);
        setalarm = false;
    }
}

void softcheck(int signum) {
    softJoin(1);
    
    for (map<string, Channel *>::iterator itr = channels.begin(); itr!=channels.end(); ++itr )
    {
        for (map<Server*,bool>::iterator iter=(*itr).second->servers.begin(); iter !=(*itr).second->servers.end(); iter++)
        {
            if ((*iter).second) {
                (*iter).second = false;
            }else{
                (*itr).second->servers.erase(iter);
            }
        }
    }
    setalarm = true;
    signal(SIGALRM, softJoin);
	alarm(60);
}



int main(int argc, char* argv[])
{
    
    
	
    int port;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
    /*
    if (argc != 3){
        fprintf(stderr, "Usage: ./server domain_name port_num\n");
        return 1;
    }
    */
	struct sockaddr_storage *their_addr = (struct sockaddr_storage*) malloc(sizeof(struct sockaddr_storage));
	s2s_say *buf = (s2s_say*) malloc(sizeof(request_say));
	socklen_t addr_len;
	char s[INET_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to force IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

    char *serverName =  argv[1];
    char *portNum =     argv[2];
    char serverIps[INET_ADDRSTRLEN];
    
    struct hostent *teHost = gethostbyname(serverName);
    struct in_addr ** Taddr_list = (struct in_addr **) teHost->h_addr_list;
    
    strcpy(serverIps, inet_ntoa(*Taddr_list[0]));
    
    MYIPNUM = serverIps;
    MYPORTNUM = portNum;
	if ((rv = getaddrinfo(serverName, portNum, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

    for (int i = 3; i<argc; i+=2)
    {
        struct hostent *tHost;
        struct in_addr ** addr_list;

        char *nServerName =  argv[i];
        char *nPortNum =     argv[i+1];

        Server * serv = new Server(nServerName, nPortNum);
        char buf[23];



        tHost = gethostbyname(serv->name);
        addr_list = (struct in_addr **) tHost->h_addr_list;

        strcpy(serv->ip, inet_ntoa(*addr_list[0]));
        sprintf(buf,"%s:%s", serv->ip,nPortNum);
        string key = buf;
        servers.insert(pair <string, Server*>(key, serv));



    }


	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}
    
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    
    
    signal(SIGALRM, softJoin);
	alarm(60);
   // signal(SIGALRM, softcheck);
	//alarm(10);
    

    while(1){

        
        addr_len = sizeof *their_addr;
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
                                 (struct sockaddr *)their_addr, &addr_len)) == -1) {
            //perror("recvfrom");
            //exit(1);
        }
        if(numbytes>0){
        struct sockaddr_in *q = (struct sockaddr_in *)their_addr;
        port = ntohs(q->sin_port);
        /*
         printf("listener: got packet from %s::%d\n",
         inet_ntop(their_addr->ss_family,
         get_in_addr((struct sockaddr *)their_addr),
         s, sizeof s),port);
         */
        // printf("listener: packet is %d bytes long\n", numbytes);
        //buf[numbytes] = '\0';

        buf->req_type = ntohl(buf->req_type);
        
        
        if (buf->req_type == REQ_LOGIN) {
            cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Login " << endl;
            request_login *logreq = (request_login *) buf;
            login(logreq,&their_addr, sockfd);
        }
            else if (buf->req_type == REQ_JOIN) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Join ";
                request_join *joinreq = (request_join *) buf;
                if(sizeof(*joinreq)==sizeof(request_join)){
                    cout << joinreq->req_channel << endl;
                    join(joinreq,their_addr, sockfd);
                }

            }else if (buf->req_type == REQ_LEAVE) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Leave ";
                request_leave *leavereq = (request_leave *) buf;
                if(sizeof(*leavereq)==sizeof(request_leave)){
                    cout << leavereq->req_channel << endl;
                    leave(leavereq,their_addr, sockfd);
                }
            }else if (buf->req_type == REQ_SAY) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Say ";
                request_say *sayreq = (request_say *) buf;
                if(sizeof(*sayreq)>=sizeof(request_say)){
                    cout << sayreq->req_channel << " \"" << sayreq->req_text << "\""<<endl;
                    say(sayreq, their_addr, sockfd);
                }
            }else if (buf->req_type == REQ_LIST) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request List " << endl;
                request_list *listreq = (request_list *) buf;
                if(sizeof(*listreq)==sizeof(request_list))
                    list_r(listreq, their_addr, sockfd);
            }else if (buf->req_type == REQ_WHO) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Who " << endl;
                request_who *whoreq = (request_who *) buf;
                if(sizeof(*whoreq)==sizeof(request_who))
                    who(whoreq, their_addr, sockfd);
            }else if (buf->req_type == REQ_LOGOUT) {
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request Logout " << endl;
                request_logout *logoutreq = (request_logout *) buf;
                if(sizeof(*logoutreq) == sizeof(request_logout))
                    logout(logoutreq, their_addr, sockfd);
            }else if (buf->req_type == REQ_S2S_JOIN){
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request S2S Join ";

                s2s_join *joinreq = (s2s_join *) buf;
                cout << joinreq->req_channel << endl;

                subscribe(joinreq,their_addr, sockfd);
            }else if (buf->req_type == REQ_S2S_SAY){
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request S2S Say ";
                s2s_say *sayreq = (s2s_say *) buf;
                cout << sayreq->username << " " << sayreq->req_channel << " \"" << sayreq->req_text << "\""<<endl;

                s2s_sayReq(sayreq,their_addr, sockfd);
            }else if (buf->req_type == REQ_S2S_LEAVE){
                cout<< serverIps << ":" << portNum << " " << ipportkey(their_addr) << " recv Request S2S Leave " << endl;
                s2s_leave *leavereq = (s2s_leave *) buf;
                cout << leavereq->req_channel << endl;
                s2s_leaveReq(leavereq,their_addr, sockfd);
            }
    }
    }
    freeaddrinfo(servinfo);

	close(sockfd);
	return 0;
}

void login(request_login *logreq,struct sockaddr_storage ** their_addr, int sockfd){
    char username[33];
    memset(username, '\0', 33);
    strncpy(username, logreq->req_username, USERNAME_MAX);

    User * user = new User(username,(*their_addr));
    users[ipportkey((*their_addr))]=user;

    *their_addr = (struct sockaddr_storage*) malloc(sizeof(struct sockaddr_storage));
    //printf("User %s logged in.\n");
}

void logout(request_logout *logoutreq,struct sockaddr_storage * their_addr, int sockfd){
    for (map<string, Channel *>::iterator itr = channels.begin(); itr!=channels.end(); ++itr )
    {
        Channel * chan = (*itr).second;
        if (chan != NULL)
        {
            chan->users.erase(users[ipportkey(their_addr)]);
            if (chan->users.size() == 0)
            {
                //channels.erase(itr);
               // delete chan;

            }

        }
    }
	users[ipportkey(their_addr)] = NULL;
	delete users[ipportkey(their_addr)];
}

void join(request_join *joinreq,struct sockaddr_storage * their_addr, int sockfd){
    User * user = users[ipportkey(their_addr)];
    char chanName[33];
    memset(chanName, '\0', 33);
    strncpy(chanName, joinreq->req_channel, CHANNEL_MAX);

    map<string,Channel *>::iterator itr =channels.find(chanName);

	if(itr == channels.end() || (*itr).second == NULL) {
		if(channels.size() > CHANNEL_MAX)
        {
            sendErrorPack(user, "There are currently too many channels.", sockfd);
            return;
        }
        channels[(string)chanName] = new Channel(chanName);


        for (map<string, Server*>::iterator itr = servers.begin(); itr!=servers.end(); ++itr )
        {
            struct addrinfo hints, *servinfo;

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET; // set to AF_INET to force IPv4
            hints.ai_socktype = SOCK_DGRAM;

            getaddrinfo((*itr).second->ip, (*itr).second->port, &hints, &servinfo);

            struct s2s_join packet;
            memset(&packet, '\0', sizeof(packet));
            packet.req_type = REQ_S2S_JOIN;
            strncpy(packet.req_channel, chanName, 32);
            
            cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<(*itr).second->ip<<":"<<(*itr).second->port<<" send S2S Join " << chanName << endl;
            
            sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
            channels[chanName]->servers.insert(pair<Server*,bool>( (*itr).second, true));

        }

    }
    if (!UserInChan(user, channels[chanName])){
        user->channels.insert(channels[chanName]);
        channels[chanName]->users.insert(user);
    }

}

void s2s_leaveReq(s2s_leave *leavereq,struct sockaddr_storage *their_addr, int sockfd){
    //channels[leavereq->req_channel].servers.erase(servers.find(servers[ipportkey(their_addr)]));
    //set<servers *>::iterator itr;
    //itr = chan->users.find(user);
    
    Server *servp = servers[ipportkey(their_addr)];
    if (channels[leavereq->req_channel] == NULL)
    {
        return;
    }
    
    
    channels[leavereq->req_channel]->servers.erase(servp);
    
    if(channels[leavereq->req_channel]!=NULL){
        if (channels[leavereq->req_channel]->users.empty() && channels[leavereq->req_channel]->servers.size() == 1) {
            map<Server*,bool>::iterator itr = channels[leavereq->req_channel]->servers.begin();
            
            struct addrinfo hints, *servinfo;
            
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET; // set to AF_INET to force IPv4
            hints.ai_socktype = SOCK_DGRAM;
            
            getaddrinfo((*itr).first->ip, (*itr).first->port, &hints, &servinfo);
            
            struct s2s_leave packet;
            memset(&packet, '\0', sizeof(packet));
            packet.req_type = htonl(REQ_S2S_LEAVE);
            strncpy(packet.req_channel, leavereq->req_channel, CHANNEL_MAX);
            cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<(*itr).first->ip<<":"<<(*itr).first->port<<" send S2S Leave " << leavereq->req_channel << endl;
            sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
            channels.erase(leavereq->req_channel);
            return;
        }
    }else{
        return;
    }                                                                                                
}

long long uniqueIdGen()
{
    long long ID = 0LL;
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    read(fd, &ID, 8);
    close(fd);
    
    return ID;
}

void s2s_sayReq(s2s_say *sayreq,struct sockaddr_storage *their_addr, int sockfd){
    struct text_say pack;
    pack.txt_type = htonl(TXT_SAY);
    strncpy(pack.txt_channel, sayreq->req_channel,CHANNEL_MAX);
    strncpy(pack.txt_username,sayreq->username,USERNAME_MAX);
    strncpy(pack.txt_text, sayreq->req_text,SAY_MAX);
    //sayreq->unique_id = sayreq->unique_id;
    
    for (list<long long>::iterator iter = uniqueid.begin(); iter != uniqueid.end(); iter++)
    {
        if (sayreq->unique_id == (*iter))
        {
            struct addrinfo hints, *servinfo;
            
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET; // set to AF_INET to force IPv4
            hints.ai_socktype = SOCK_DGRAM;
            Server* serv = servers[ipportkey(their_addr)];
            channels[sayreq->req_channel]->servers.erase(serv);       //erase server from my chan.servlist
            getaddrinfo(serv->ip, serv->port, &hints, &servinfo);
            
            struct s2s_leave packet;
            memset(&packet, '\0', sizeof(packet));
            packet.req_type = htonl(REQ_S2S_LEAVE);
            strncpy(packet.req_channel, sayreq->req_channel, CHANNEL_MAX);
            
            cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<serv->ip<<":"<<serv->port<<" send S2S Leave " << sayreq->req_channel << endl;

            sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
            return;

        }
    }
    
    uniqueid.push_front(sayreq->unique_id);
    
    if (uniqueid.size() >50)
        uniqueid.pop_back();
    
    //cout << sayreq->req_channel << endl;
    //this unsubscribes

    if(channels[sayreq->req_channel]!=NULL){
    if (channels[sayreq->req_channel]->users.empty() && channels[sayreq->req_channel]->servers.size() == 1) {

        
        map<Server*,bool>::iterator itr = channels[sayreq->req_channel]->servers.begin();
        
        struct addrinfo hints, *servinfo;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // set to AF_INET to force IPv4
        hints.ai_socktype = SOCK_DGRAM;

        getaddrinfo((*itr).first->ip, (*itr).first->port, &hints, &servinfo);
        channels.erase(sayreq->req_channel);
        
        struct s2s_leave packet;
        memset(&packet, '\0', sizeof(packet));
        packet.req_type = htonl(REQ_S2S_LEAVE);
        strncpy(packet.req_channel, sayreq->req_channel, CHANNEL_MAX);
        cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<(*itr).first->ip<<":"<<(*itr).first->port<<" send S2S Leave " << sayreq->req_channel << endl;
        sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
        
        return;
    }
    }else{
        return;
    }
    
    string ipPort= ipportkey(their_addr);
    string word;
    char theirIp[64];
    char theirPort [6];
        stringstream stream(ipPort);

    getline(stream, word, ':');
        strncpy(theirPort, word.c_str(), word.length());
    getline(stream, word, ':');
        strncpy(theirIp, word.c_str(), word.length());
    
    char s[INET_ADDRSTRLEN];
    char portchar[6];
    struct sockaddr_in *q = (struct sockaddr_in *)their_addr;
    int port = ntohs(q->sin_port);
    string ip = inet_ntop(their_addr->ss_family, get_in_addr((struct sockaddr *)their_addr), s, sizeof s);
    sprintf(portchar,"%d",port);
    string Result = portchar;
    Result+=':';
    Result+=ip;
    strncpy(theirPort, portchar, 6);
    strncpy(s, ip.c_str(), ip.length());

/*
 
    ///broadcast say message
    cout << "before" << endl;
    string str = sayreq->req_channel;


        for(map<string, Channel*>::iterator itr = channels.begin(); itr != channels.end(); itr++)
    {
        cout << itr->first << endl;
    }

    map<string,Channel *>::iterator itr =channels.find(str);*/
    //cout << "after" << endl;
    Channel *chan = channels[sayreq->req_channel];
    for (map<Server*,bool>::iterator ittr= chan->servers.begin(); ittr!=chan->servers.end(); ittr++)
    {

        if (strcmp((*ittr).first->ip, s) != 0 || strcmp((*ittr).first->port, theirPort) != 0)
        {
            /*
            cout << "SENDING S2S SAY TO THIS GUY" << endl;
            cout << "ip: [" <<(*ittr)->ip << " " << s <<"]"<< endl;
            cout << "port: [" << (*ittr)->port << " " << portchar << "]" << endl;*/
                struct addrinfo hints, *servinfo;

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_INET; // set to AF_INET to force IPv4
                hints.ai_socktype = SOCK_DGRAM;

                getaddrinfo((*ittr).first->ip, (*ittr).first->port, &hints, &servinfo);



                struct s2s_say packet;
                memset(&packet, '\0', sizeof(packet));
                packet.req_type = htonl(REQ_S2S_SAY);
            packet.unique_id = sayreq->unique_id;
                strncpy(packet.req_channel, sayreq->req_channel, CHANNEL_MAX);
                strncpy(packet.username, pack.txt_username, USERNAME_MAX);
                strncpy(packet.req_text, sayreq->req_text, SAY_MAX);
            cout<< MYIPNUM << ":" << MYPORTNUM <<" "<< (*ittr).first->ip <<":"<<(*ittr).first->port<<" send S2S Say " << pack.txt_username << " "<< pack.txt_channel;
            cout << " \"" << pack.txt_text << "\"" << endl;
                sendto(sockfd, &packet, sizeof(s2s_say), 0, servinfo->ai_addr, servinfo->ai_addrlen);
       }
    } 
    //cout << "asdf" << endl;

    for(set<User*>::iterator iter = channels[sayreq->req_channel]->users.begin(); iter!=channels[sayreq->req_channel]->users.end(); iter++){

        //cout << "to " << (*iter)->ip << ":" << (*iter)->port << endl;
        //ipportkey((*iter)->addrinf);

        struct addrinfo hints, *servinfo;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // set to AF_INET to force IPv4
        hints.ai_socktype = SOCK_DGRAM;

        getaddrinfo((*iter)->ip, (*iter)->port, &hints, &servinfo);
        cout<< MYIPNUM << ":" << MYPORTNUM <<" "<< (*iter)->ip <<":"<<(*iter)->port<<" send Say " << pack.txt_username << " "<< pack.txt_channel;
        cout << " \"" << pack.txt_text << "\"" << endl;
        int status = sendto(sockfd, &pack, sizeof(text_say), 0, servinfo->ai_addr, servinfo->ai_addrlen);
        //cout << status<<endl;
        //int status = sendto(sockfd, &pack, sizeof(text_say), 0, (sockaddr*)(*iter)->addrinf, sizeof(sockaddr));
    }


}


void subscribe(s2s_join *joinreq,struct sockaddr_storage * their_addr, int sockfd)
{
    char chanName[CHANNEL_MAX+1];
    memset(chanName, '\0', CHANNEL_MAX+1);
    strncpy(chanName, joinreq->req_channel, CHANNEL_MAX);

    map<string, Channel*>::iterator itr = channels.find(chanName);

    if(itr == channels.end() ) {
		channels[(string)chanName] = new Channel(chanName);

        for (map<string, Server*>::iterator itr = servers.begin(); itr!=servers.end(); ++itr )
        {
            struct addrinfo hints, *servinfo;

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET; // set to AF_INET to force IPv4
            hints.ai_socktype = SOCK_DGRAM;

            getaddrinfo((*itr).second->ip, (*itr).second->port, &hints, &servinfo);

            struct s2s_join packet;
            memset(&packet, '\0', sizeof(packet));
            packet.req_type = htonl(REQ_S2S_JOIN);
            strncpy(packet.req_channel, chanName, 32);
            
            cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<(*itr).second->ip<<":"<<(*itr).second->port<<" send S2S Join " << chanName << endl;
            
            sendto(sockfd, &packet, 36, 0, servinfo->ai_addr, servinfo->ai_addrlen);
            channels[chanName]->servers.insert(pair<Server*,bool>( (*itr).second, true) );

        }

    }else{
        //(*itr).second->servers.insert( pair<Server*,bool>( servers[ipportkey(their_addr)], true));
        (*itr).second->servers[servers[ipportkey(their_addr)]] = true;
    }
}

void leave(request_leave *leavereq,struct sockaddr_storage * their_addr, int sockfd){
    User * user = users[ipportkey(their_addr)];

    char chanName[CHANNEL_MAX+1];
    memset(chanName, '\0', CHANNEL_MAX+1);
    strncpy(chanName, leavereq->req_channel, CHANNEL_MAX);
    Channel *chan = channels[chanName];

    map<string, Channel *>::iterator itr = channels.find(chanName);

    if (itr == channels.end() || (*itr).second == NULL)
        sendErrorPack(users[ipportkey(their_addr)], "Channel not found.", sockfd);
    else
    {
        user->channels.erase(chan);
        channels[chanName]->users.erase(user);
        /*
            if (chan->users.size() == 0)
            {
                channels.erase(itr);
                delete chan;
            }
        */
    }

}

void say(request_say *sayreq,struct sockaddr_storage * their_addr, int sockfd){
    struct text_say pack;
    pack.txt_type = htonl(TXT_SAY);
    strncpy(pack.txt_channel, sayreq->req_channel,CHANNEL_MAX);
    User* user = users[ipportkey(their_addr)];
    strncpy(pack.txt_username,user->name.c_str(),USERNAME_MAX);
    strncpy(pack.txt_text, sayreq->req_text,SAY_MAX);
    
    
    struct s2s_say packet;
    memset(&packet, '\0', sizeof(packet));
    
    packet.unique_id= uniqueIdGen();
    uniqueid.push_front(packet.unique_id);
    packet.req_type = htonl(REQ_S2S_SAY);

    strncpy(packet.req_channel, sayreq->req_channel, CHANNEL_MAX);
    strncpy(packet.username, pack.txt_username, USERNAME_MAX);
    strncpy(packet.req_text, sayreq->req_text, SAY_MAX);
    //cout << packet.req_channel << endl;
    //cout << sizeof(packet) << endl;
    ///broadcast say message
    for (map<Server*,bool>::iterator ittr= channels[sayreq->req_channel]->servers.begin(); ittr!=channels[sayreq->req_channel]->servers.end(); ittr++)
    {

                struct addrinfo hints, *servinfo;

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_INET; // set to AF_INET to force IPv4
                hints.ai_socktype = SOCK_DGRAM;

                getaddrinfo((*ittr).first->ip, (*ittr).first->port, &hints, &servinfo);



        cout<< MYIPNUM << ":" << MYPORTNUM <<" "<< (*ittr).first->ip <<":"<<(*ittr).first->port<<" send S2S Say " << pack.txt_username << " "<< pack.txt_channel;
        cout << " \"" << pack.txt_text << "\"" << endl;

                sendto(sockfd, &packet, sizeof(s2s_say), 0, servinfo->ai_addr, servinfo->ai_addrlen);


    }

    for(set<User*>::iterator iter = channels[sayreq->req_channel]->users.begin(); iter!=channels[sayreq->req_channel]->users.end(); iter++){
        //printf("%s:%s:%s\n",pack.txt_username,pack.txt_text,pack.txt_channel);

        //cout << "to " << (*iter)->ip << ":" << (*iter)->port << endl;
        //ipportkey((*iter)->addrinf);

        struct addrinfo hints, *servinfo;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // set to AF_INET to force IPv4
        hints.ai_socktype = SOCK_DGRAM;

        getaddrinfo((*iter)->ip, (*iter)->port, &hints, &servinfo);
        
        cout<< MYIPNUM << ":" << MYPORTNUM <<" "<< (*iter)->ip <<":"<<(*iter)->port<<" send Say " << pack.txt_username << " "<< pack.txt_channel;
        cout << " \"" << pack.txt_text << "\"" << endl;
        
        int status = sendto(sockfd, &pack, sizeof(text_say), 0, servinfo->ai_addr, servinfo->ai_addrlen);
        //cout << status<<endl;
        //int status = sendto(sockfd, &pack, sizeof(text_say), 0, (sockaddr*)(*iter)->addrinf, sizeof(sockaddr));
    }

}

void list_r(request_list *listreq,struct sockaddr_storage * their_addr, int sockfd){
    User * user = users[ipportkey(their_addr)];

    int pktsize = (channels.size()* sizeof(channel_info))+sizeof(text_list);
    struct text_list * listPacket = (text_list*) malloc(pktsize);
    memset(listPacket, '\0', pktsize);

    listPacket->txt_type = htonl(TXT_LIST);
    listPacket->txt_nchannels = htonl(channels.size());

    int x = 0;
    for(map<string, Channel*>::iterator itr = channels.begin(); itr != channels.end(); ++itr)
    {
        strncpy(listPacket->txt_channels[x].ch_channel, itr->first.c_str(), CHANNEL_MAX);
        x++;
    }

    cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<user->ip <<":"<<user->port<<" send list " << endl;

    sendto(sockfd, listPacket, pktsize, 0, (sockaddr*) user->addrinf, sizeof(sockaddr));
    free(listPacket);


}

void sendErrorPack(User * user, string str, int sockfd)
{

    struct text_error packet;
    packet.txt_type = TXT_ERROR;
    strncpy(packet.txt_error, str.c_str(), SAY_MAX);
    
    cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<user->ip <<":"<<user->port<<" send error " << endl;
    
    sendto(sockfd, &packet, sizeof(text_error), 0, (sockaddr*)user->addrinf, sizeof(sockaddr));
}

void who(request_who *whoreq,struct sockaddr_storage * their_addr, int sockfd){
    User * user = users[ipportkey(their_addr)];
    char chanName[CHANNEL_MAX+1];
    memset(chanName, '\0', CHANNEL_MAX+1);
    strncpy(chanName, whoreq->req_channel, CHANNEL_MAX);

    if (channels[chanName] == NULL)
    {
        sendErrorPack(user, "Channel doesn't exist.", sockfd);
        return;
    }

    int x = channels[chanName]->users.size();
    int pktsize = sizeof(text_who) + (x*sizeof(user_info));
    struct text_who * packet = (text_who*) malloc(pktsize);
    memset(packet, '\0', pktsize);
    packet->txt_type = TXT_WHO;
    packet->txt_nusernames = x;

    strncpy(packet->txt_channel, channels[chanName]->name.c_str(), CHANNEL_MAX);

    int n = 0;
    for (set<User*>::iterator itr = channels[chanName]->users.begin(); itr != channels[chanName]->users.end(); itr++)
    {
        strncpy(packet->txt_users[n].us_username, (*itr)->name.c_str(), USERNAME_MAX);
        n++;
    }
    cout<< MYIPNUM << ":" << MYPORTNUM <<" "<<user->ip <<":"<<user->port<<" send who " << chanName << endl;

    sendto(sockfd, packet, pktsize, 0, (sockaddr*)user->addrinf, sizeof(sockaddr));

    free(packet);
}

string ipportkey(struct sockaddr_storage *their_addr){
	char s[INET_ADDRSTRLEN];
    char portchar[6];
    struct sockaddr_in *q = (struct sockaddr_in *)their_addr;
    int port = ntohs(q->sin_port);
    string ip = inet_ntop(their_addr->ss_family, get_in_addr((struct sockaddr *)their_addr), s, sizeof s);
    sprintf(portchar,"%d",port);
    string Result = ip;
    Result+=':';
    Result+=portchar;
    return Result;
}
