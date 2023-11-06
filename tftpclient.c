
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <unistd.h>


#define ASSERT(_bool, ...) do{if (!(_bool)) fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE);}while(0);
#define VERBOSE_MSG(msg,...) do{if(verbose_flag) fprintf(stdout,msg,__VA_ARGS__);}while(0);

#define RRQ 0x01 // [opcode-2B][filename-xB][0(EOS)-1B][mode-yB][0(EOS)-1B]
#define WRQ 0x02
#define DATA 0x03
#define ACK 0x04
#define ERROR 0x05

int verbose_flag = 1;

int main(int argc, char** argv){

    int aux;
    int sockfd;
    struct in_addr addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in my_addr = {.sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = INADDR_ANY};

    memset(&addr, 0, sizeof(addr));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&my_addr, 0, sizeof(my_addr));

    //ASSERT(argc == 4, "Uso: %s ip_servidor {-r|-w} archivo [-v]",argv[0]);

    if(strcmp(argv[4],"-v")==0){
        verbose_flag = 1;
    }


}