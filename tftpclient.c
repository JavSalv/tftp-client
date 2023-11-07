
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <unistd.h>

#pragma pack(2)


#define ASSERT(_bool, ...) do{if (!(_bool)){ fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE);}}while(0);
#define VERBOSE_MSG(msg,...) do{if(verbose_flag) fprintf(stdout,msg,__VA_ARGS__);}while(0);

#define RRQ (unsigned short)0x01 // [opcode-2B][filename-xB][0(EOS)-1B][mode-yB][0(EOS)-1B]
#define WRQ (unsigned short)0x02 // [opcode-2B][filename-xB][0(EOS)-1B][mode-yB][0(EOS)-1B]
#define DATA (unsigned short)0x03 // [opcode-2B][block#-2B][data(0-512)B]
#define ACK (unsigned short)0x04 // [opcode-2B][block#-2B]
#define ERROR (unsigned short)0x05 // [opcode-2B][errcode-2B][errstring-zb][0(EOS)-1B]

#define SERVER_PORT 69

int verbose_flag = 0;




void tftp_readfile(int sockfd, struct sockaddr_in* server_addr, const char* filename){

    char* rrq_payload = (char*)malloc(2+strlen(filename)+1+strlen("aa")+1);

    rrq_payload[0]=0xf0 & RRQ;
    rrq_payload[1]=0x0f & RRQ;

    strcpy(rrq_payload+2,filename);

    //De momento solo modo octet
    strcpy(rrq_payload+2+strlen(filename)+1,"octet");
    //Payload completo

    
    
}

int main(int argc, char** argv){

    int aux;
    int sockfd;
    struct in_addr addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in my_addr = {.sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = INADDR_ANY};

    memset(&addr, 0, sizeof(addr));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&my_addr, 0, sizeof(my_addr));

    ASSERT((argc == 4 || argc == 5), "Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);

    ASSERT((inet_aton(argv[1], &addr) == 1), "Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);

    server_addr.sin_port = SERVER_PORT;
    server_addr.sin_addr = addr;
    server_addr.sin_family = AF_INET;

    if(argc == 5 && strcmp(argv[4],"-v")==0){
        verbose_flag = 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(sockfd !=-1, "Error creando socket: %s\n",strerror(errno));

    aux = bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    ASSERT(aux == 0, "Error vinculando socket: %s\n", strerror(errno));
    printf("%s",argv[2]);
    if (strcmp(argv[2], "-r") == 0)
    {
        tftp_readfile(sockfd, &server_addr, argv[3]);
    }
    else if (strcmp(argv[2], "-w") == 0)
    {
    }
}

