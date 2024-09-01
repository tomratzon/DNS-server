#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PORT 1053 //used port for hour DNS server
#define BUF_SIZE 512 //standart buffer size
#define MAX_DOMAINS 100 //max enteries in hostfile.txt
#define HOSTS_FILE "hostfile.txt" //cache file of the dns server

// flag to enable forwarding to another DNS server( 1 to enable)
#define ENABLE_FORWARDING 1

// the external DNS server forwarding data - ip and port 
#define FORWARD_DNS_SERVER "192.0.5.1"
#define FORWARD_DNS_PORT 1054


// structure for host entery: hostname and ip
typedef struct {
    char hostname[256];
    char ip[16];
} HostEntry;

HostEntry hosts[MAX_DOMAINS]; //array of host entry struturse
int host_count = 0;


void load_hosts_file() {
//read hostfile.txt enteries into hosts array
    FILE *file = fopen(HOSTS_FILE, "r"); 
    if (!file) { 
        perror("error opening hosts.txt\n");
        exit(EXIT_FAILURE);
    }

    char line[512];
    while (fgets(line, sizeof(line), file) && host_count < MAX_DOMAINS) {
        char *curr_read = strtok(line, ":"); //read hostname to curr_read
        if (curr_read) {
            strcpy(hosts[host_count].hostname, curr_read);//copy curr_read to the araay (hostname)
            curr_read = strtok(NULL, "\n"); //read ip to curr_read
            if (curr_read) {
                strcpy(hosts[host_count].ip, curr_read);//copy curr_read to the araay (ip)
                host_count++;
            }
        }
    }
    fclose(file);
}

char *lookup_ip(const char *hostname) {
//look for the matching ip of the given hostname
    for (int i = 0; i < host_count; i++) {
        if (strcmp(hosts[i].hostname, hostname) == 0) {
            return hosts[i].ip;
        }
    }
    return NULL;
}
// Function to convert a string IP address to binary format (replacing inet_pton)
void ip_to_binary(const char *ip_str, unsigned char *binary_ip) {
    int segments[4]; // To hold each segment of the IP address
    sscanf(ip_str, "%d.%d.%d.%d", &segments[0], &segments[1], &segments[2], &segments[3]);

    for (int i = 0; i < 4; i++) {
        binary_ip[i] = (unsigned char)segments[i];
    }
}

void parse_qname(unsigned char *qname, char *hostname) {
//parsing the hostname from the qname DNS format (0x3www0x7testing0x3com -> www.testing.com)

    int pos = 0;  // index in the domain_name
    int i = 0;    // index in the qname

    while (qname[i] != 0) {
        int label_len = qname[i];  // length of the label
        i++;  
        for (int j = 0; j < label_len; j++) {
            hostname[pos++] = qname[i++]; // copy the label into hostname
        }
        hostname[pos++] = '.';  // add a dot after the label
    }
    hostname[pos - 1] = '\0';// replace the last dot with '\0'
}

void forward_query(int sockfd, struct sockaddr_in *client_addr, socklen_t client_len, unsigned char *buffer, int len) {
//this function forward the the DNS queue to the next DNS server via new socket
    int forward_sock;
    struct sockaddr_in forward_addr;
    
    forward_sock = socket(AF_INET, SOCK_DGRAM, 0); //new socket to communicate the next DNS
    if (forward_sock < 0) {
        perror("Socket creation for forward DNS failed");
        return;
    }

    memset(&forward_addr, 0, sizeof(forward_addr)); //
    forward_addr.sin_family = AF_INET; //ipv4 family
    forward_addr.sin_port = htons(FORWARD_DNS_PORT); //port to listen 1054

    if (inet_pton(AF_INET, FORWARD_DNS_SERVER, &forward_addr.sin_addr) <= 0) { //translate the ip of the next DNS server to bytes
        perror("invalid DNS server address");
        close(forward_sock);
        return;
    }

    // send new query to the forward DNS server with the original question
    if (sendto(forward_sock, buffer, len, 0, (struct sockaddr *)&forward_addr, sizeof(forward_addr)) < 0) {
        perror("forwarding query failed");
        close(forward_sock);
        return;
    }

    // receiving a response from the next DNS server
    unsigned char response[BUF_SIZE];
    int response_len = recvfrom(forward_sock, response, BUF_SIZE, 0, NULL, NULL);
    if (response_len < 0) {
        perror("receiving response from S DNS failed");
        close(forward_sock);
        return;
    }

    // send the received response back to the original DNS server
    sendto(sockfd, response, response_len, 0, (struct sockaddr *)client_addr, client_len);
    close(forward_sock);
    printf("Response forwarded from external DNS server\n");
}

//this function will handle incoming DNS queries, analize them, construct a respone and send it back to sender
void handle_dns_query(int sockfd, struct sockaddr_in *client_addr, socklen_t client_len, unsigned char *buffer, int len) {
    unsigned char *qname = &buffer[12]; //question section starts after 12 bytes of the DNS header

    char hostname[256];
    parse_qname(qname, hostname);  //convert qname dns foemat to hostname string

    char *response_ip = lookup_ip(hostname); //check for matching ip in hosts array
    
    if (!response_ip) {
     // If no match is found, check if forwarding is enabled
        if (ENABLE_FORWARDING) {
            printf("no match found for %s, forwarding query\n", hostname);
            forward_query(sockfd, client_addr, client_len, buffer, len);
        } 
        else {
            printf("No match found for %s and forwarding is disabled, responding with NXDOMAIN\n", hostname);
        unsigned char response[BUF_SIZE];
        memset(response, 0, BUF_SIZE);

        // copy the header part
        memcpy(response, buffer, 12);

        // 0x8183 ->RCODE=3 (NXDOMAIN)
        response[2] = 0x81; // QR = 1 (response), Opcode = 0 (standard query), AA = 0 (not authoritative)
        response[3] = 0x83; // RA = 0, Z = 0, RCODE = 3 (NXDOMAIN)
        response[7] = 0x00; // Answer count = 0

        // Question section (unchanged same as DNS query )
        int offset = len;
        memcpy(&response[12], qname, len - 12);

        // Send the NXDOMAIN response
        sendto(sockfd, response, offset, 0, (struct sockaddr *)client_addr, client_len);
        printf("NXDOMAIN response sent for %s\n", hostname);
        printf("_______________________________\n");
        }
    } 
    else {
     printf("________Response________\n");
        printf("IP found for %s, responding with IP: %s\n", hostname, response_ip);
    

    // Strarting to construct DNS response for a match:
//__________________________________________________________________________________________________________-
    unsigned char response[BUF_SIZE];
    memset(response, 0, BUF_SIZE);

    // DNS header
    memcpy(response, buffer, 12); //copy DNS header from buffer

    // set the flags to 0x8180
    response[2] = 0x81; // QR = 1 (response), Opcode = 0 (standard query), AA = 0 (not authoritative)
    response[3] = 0x80; // RA = 0, Z = 0, RCODE = 0 (No error)
    response[7] = 1;    // answer count = 1

    // question section (unchanged - same qname,type and class)
    int res_index = len;
    memcpy(&response[12], qname, len - 12);

    // answer section for 
    //***************************
    response[res_index++] = 0xc0; // Pointer to the hostname in the question section
    response[res_index++] = 0x0c; //define a pointer to look at the sectio after the 12 DNS server bytes

    // type A (host address)
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x01; //set to 1

    // class IN
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x01; //set to 1

    // TTL (Time to Live)
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x3c; //set to 60 = 1 min to live

    // data length (IPv4 address is 4 bytes)
    response[res_index++] = 0x00; //set to 0
    response[res_index++] = 0x04; //set to 4 - length
   

    // IP address
    ip_to_binary(response_ip,&response[res_index]); //this function translate ipv4 string id into binary byte format
    res_index += 4; // advance the res_index by 4 bytes (size of IPv4 address)
    
    //***************************
    sendto(sockfd, response, res_index, 0, (struct sockaddr *)client_addr, client_len);  // Send the response
    printf("Response sent with IP %s\n", response_ip);
    printf("________________________\n\n");
    }
}

int get_question_section_length(unsigned char *buffer) {
//calculate the length of the question section in the DNS query

    int index = 12; // DNS header is 12 bytes
    while (buffer[index] != 0) { //while no end of hostname
        index += buffer[index] + 1;
    }
    index++; // move past the null byte
    index += 4; // add size of QTYPE and QCLASS - 2 bytes for QTYPE + 2 bytes for QCLASS
    return index; // Length up to the end of the question section
}
int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned char buffer[BUF_SIZE]; //buffer to recieve the DNS query

    
    load_hosts_file(); //call for load_hosts_file in order to read enteries

    // creating UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // binding the socket to port 1053 (no specific reason for this port - 53 is the global DNS thus taken)
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; //IPV4 address familiy
    server_addr.sin_addr.s_addr = INADDR_ANY; //accept packets from any address
    server_addr.sin_port = htons(PORT); //set port to listern to (1053 in our case)

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS server is running...\n");

    // start listening to port (1053)
     while (1) {
        int len = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (len > 0) {
            // fork a new process to handle the query
            pid_t pid = fork();
            if (pid == 0) {  // Child process
                handle_dns_query(sockfd, &client_addr, client_len, buffer, len);
                exit(0);  // exit the child process after handling the query
            } else if (pid > 0) {  // parent process
                // wait for child processes to prevent zombie processes
                waitpid(-1, NULL, WNOHANG);
            } else {
                perror("fork failed");
            }
        }
    }

    close(sockfd);
    return 0;
}
