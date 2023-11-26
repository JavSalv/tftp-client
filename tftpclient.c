// Practica Tema 7: Salvador Peñacoba, Javier
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>


#define ASSERT(_bool, ...) do{if (!(_bool)){ fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE);}}while(0);
#define VERBOSE_MSG(_msg,...) do{if(verbose_flag) fprintf(stdout,_msg,__VA_ARGS__);}while(0);

#define RRQ (unsigned short)0x01 // [opcode-2B][filename-xB][0(EOS)-1B][mode-yB][0(EOS)-1B]
#define WRQ (unsigned short)0x02 // [opcode-2B][filename-xB][0(EOS)-1B][mode-yB][0(EOS)-1B]
#define DATA (unsigned short)0x03 // [opcode-2B][block#-2B][data(0-512)B]
#define ACK (unsigned short)0x04 // [opcode-2B][block#-2B]
#define ERROR (unsigned short)0x05 // [opcode-2B][errcode-2B][errstring-zb][0(EOS)-1B]

#define MAX_BLOCKSIZE 512

int verbose_flag = 0;

const char* error_msgs[]={
    "errstring",
    "Fichero no encontrado.",
    "Violación de acceso.",
    "Espacio de almacenamiento lleno.",
    "Operación TFTP ilegal.",
    "Identificador de transferencia desconocido.",
    "El fichero ya existe.",
    "Usuario desconocido."
};

//Devuelve el número del bloque al que corresponde el paquete. Se puede usar con paquetes tipo DATA y ACK.
static inline unsigned short get_payloadBlockNum(const char* payload){
    return(((unsigned char)payload[2])*256 + (unsigned char)payload[3]);
}

//Devuelve el mensaje de error asociado a un paquete tipo ERR.
static inline const char* get_error_msg(const char* payload){
    unsigned short errcode = get_payloadBlockNum(payload);
    const char* errmsg = (errcode > 0  && errcode < 8) ? error_msgs[errcode] : payload+4;
    return errmsg;
}

//Comprueba si el opcode de payload coincide con el opcode introducido.
static inline int check_opcode(char* payload, unsigned short opcode){
    return ((payload[0] << 8) | (payload[1] & 0xff)) == opcode;
}


//Genera una petición RRQ o WRQ. Devuelve el payload y almacena su longitud en payload_size.
char* create_request(const char* filename, const char* mode, unsigned short opcode, int* payload_size){
    int size = 2+strlen(filename)+1+strlen(mode)+1;
    char *payload = (char*)calloc(size,1);
    ASSERT(payload != NULL, "Error malloc: %s\n",strerror(errno));
    payload[0]= (opcode >> 8) & 0xff;
    payload[1]= opcode & 0xff;
    strcpy(payload+2,filename);
    strcpy(payload+2+strlen(filename)+1,mode);
    *payload_size = size;
    return payload;
}

void tftp_readfile(int sockfd, struct sockaddr_in* server_addr, const char* filename){
    int aux;
    FILE* dest_file = NULL;
    socklen_t addrlen = sizeof(*server_addr);
    unsigned short block_num;
    unsigned short curr_block = 1;
    unsigned int byte_count = 0;
    int block_lenght;
    char* msg_in;
    int rrq_size;

    char* msg_out = create_request(filename,"octet",RRQ,&rrq_size);

    aux = sendto(sockfd,msg_out,rrq_size,0,(struct sockaddr*)server_addr,addrlen);
    ASSERT(aux != -1, "Error enviando RRQ: %s\n",strerror(errno));
    free(msg_out);

    printf("Enviada solicitud de lectura de \"%s\" a servidor tftp en %s\n",filename,inet_ntoa(server_addr->sin_addr));

    //Recibir posible error/primer bloque.
    msg_in = (char*)calloc(MAX_BLOCKSIZE+4,1);    //Reservamos espacio para un bloque entero,2 bytes de opcode y 2 de blocknum.
    msg_out = (char*)calloc(4,1);                 //Reservamos espacio para el ack;

    ASSERT(msg_in != NULL && msg_out != NULL, "Error malloc: %s\n",strerror(errno));
    
    do{
        //Recibimos mensaje: Block/Err
        aux = recvfrom(sockfd,msg_in,MAX_BLOCKSIZE+4,0,(struct sockaddr*) server_addr,&addrlen);
        ASSERT(aux != -1, "Error recibiendo mensaje: %s\n",strerror(errno));
        
        
        //Crearemos el archivo una vez se reciba el primer bloque.
        if(dest_file == NULL){
            dest_file = fopen(filename,"wb");
        }

        //Comprobamos si es error
        if(check_opcode(msg_in,ERROR)){
            ASSERT(0,"Recibido paquete de error: %s\n",get_error_msg(msg_in));
        }

        //Comprobamos si el paquete recibido es de datos
        ASSERT(check_opcode(msg_in,DATA),"Recibido paquete que no era de datos.\n");

        //Calculamos el numero de bloque recibido.
        block_num = get_payloadBlockNum(msg_in); 

        VERBOSE_MSG("Recibido bloque de datos número %u\n",block_num);

        //Comprobamos si el bloque llega en orden.
        ASSERT(block_num == curr_block++,"Error: recibido bloque desordenado\n");

        //Escribimos el bloque en el archivo.
        block_lenght = aux - 4;
        fwrite(msg_in+4, sizeof(char),block_lenght,dest_file);
        byte_count += block_lenght;


        //Enviamos ack;
        msg_out[0]= (ACK >> 8) & 0xff;
        msg_out[1]= ACK & 0xff;
        msg_out[2]= (block_num >> 8) & 0xff;
        msg_out[3]= block_num & 0xff;

        aux = sendto(sockfd,msg_out,4,0,(struct sockaddr*)server_addr,addrlen);
        ASSERT(aux != -1, "Error enviando ACK: %s\n",strerror(errno));

        VERBOSE_MSG("Enviado ACK del block %u\n",block_num);

    }while(block_lenght >= MAX_BLOCKSIZE);

    VERBOSE_MSG("El bloque %u era el último: cerramos el fichero.\n",block_num);
    free(msg_out);
    free(msg_in);
    fclose(dest_file);

    printf("Fichero \"%s\" recibido correctamente.\n Bytes recibidos: %u\n",filename,byte_count);
    
}

void tftp_sendfile(int sockfd, struct sockaddr_in* server_addr, const char* filename){
    int aux;
    FILE* source_file = NULL;
    socklen_t addrlen = sizeof(*server_addr);
    unsigned short block_num = 0;
    unsigned int byte_count = 0;
    int block_lenght = MAX_BLOCKSIZE;
    char* msg_in;
    int wrq_size;

    //Comprobamos primero si el fichero existe.
    source_file = fopen(filename,"rb");
    ASSERT(source_file != NULL,"Error: No existe el fichero \"%s\"\n",filename);

    char* msg_out = create_request(filename,"octet",WRQ,&wrq_size);

    //Enviamos solicitud WRQ
    aux = sendto(sockfd,msg_out,wrq_size,0,(struct sockaddr*) server_addr, addrlen);
    ASSERT(aux != -1, "Error enviando WQR al servidor: %s\n",strerror(errno));
    free(msg_out);

    printf("Enviada solicitud de escritura de \"%s\" a servidor tftp en %s\n",filename,inet_ntoa(server_addr->sin_addr));

    msg_in = (char*)calloc(4,1);
    msg_out = (char*) calloc(MAX_BLOCKSIZE+4,1);

    ASSERT(msg_in != NULL && msg_out != NULL, "Error malloc: %s\n",strerror(errno));

    //El bucle se ejecutará hasta recibir el ACK del último bloque.
    while(1){
        //Recibimos ACK del bloque o error
        aux = recvfrom(sockfd,msg_in,4,0,(struct sockaddr*) server_addr, &addrlen);

        //Comprobamos si es error
        if(check_opcode(msg_in,ERROR)){
            ASSERT(0,"Recibido paquete de error: %s",get_error_msg(msg_in));
        }

        //Comprobamos que es ack y además corresponde con el bloque correcto;
        ASSERT(check_opcode(msg_in,ACK) && get_payloadBlockNum(msg_in) == block_num,"Recibido paquete incorrecto\n");

        VERBOSE_MSG("Recibido ACK del bloque %u\n",block_num);

        if(block_lenght != MAX_BLOCKSIZE) break;

        block_num++;

        //Enviamos bloque
        msg_out[0]= (DATA >> 8) & 0xff;
        msg_out[1]= DATA & 0xff;
        msg_out[2]= (block_num >> 8) & 0xff;
        msg_out[3]= block_num & 0xff;

        block_lenght = fread(msg_out+4,sizeof(char),MAX_BLOCKSIZE,source_file);

        byte_count += block_lenght;

        aux = sendto(sockfd,msg_out,block_lenght+4,0,(struct sockaddr*) server_addr, addrlen);
        ASSERT(aux != -1, "Error enviando bloque de datos: %s\n",strerror(errno));

        VERBOSE_MSG("Enviado bloque de datos número %u\n",block_num)
    }
    VERBOSE_MSG("El bloque %u era el último: cerramos el fichero.\n",block_num);
    free(msg_out);
    free(msg_in);
    fclose(source_file);

    printf("Fichero \"%s\" enviado correctamente.\n Bytes enviados: %u\n",filename,byte_count);
}

int main(int argc, char** argv){

    int aux;
    int sockfd;
    struct servent* service;
    struct in_addr addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in my_addr = {.sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = INADDR_ANY};

    memset(&addr, 0, sizeof(addr));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&my_addr, 0, sizeof(my_addr));

    ASSERT((argc == 4 || argc == 5), "Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);

    ASSERT((inet_aton(argv[1], &addr) == 1), "Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);

    service = getservbyname("tftp","udp");
    ASSERT(service != NULL, "Error encontrando el puerto asociado al servicio tftp.\n");

    server_addr.sin_port = service->s_port;
    server_addr.sin_addr = addr;
    server_addr.sin_family = AF_INET;

    if(argc == 5){
        ASSERT(strcmp(argv[4],"-v")==0,"Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);
        verbose_flag = 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(sockfd !=-1, "Error creando socket: %s\n",strerror(errno));

    aux = bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    ASSERT(aux == 0, "Error vinculando socket: %s\n", strerror(errno));

    if (strcmp(argv[2], "-r") == 0)
    {
        tftp_readfile(sockfd, &server_addr, argv[3]);
    }
    else if (strcmp(argv[2], "-w") == 0)
    {
        tftp_sendfile(sockfd,&server_addr,argv[3]);
    }
    else{
        ASSERT(0, "Uso: %s ip_servidor {-r|-w} archivo [-v]\n",argv[0]);
    }

    close(sockfd);
    return 0;
}

