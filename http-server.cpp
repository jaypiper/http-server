#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <iostream>
#include <cassert>

using namespace std;

#define HPPTPORT 80
#define BUFSZ 4096

int main() {
  int sockfd = socket(PF_INET, SOCK_STREAM, 0);
  assert(sockfd != -1);

  sockaddr_in http_addr = {.sin_family = AF_INET, .sin_port = (in_port_t)htons(HPPTPORT), .sin_addr = {.s_addr=htonl(INADDR_ANY)}};
  assert(bind(sockfd, (struct sockaddr*)&http_addr, sizeof(http_addr)) != -1);
  assert(listen(sockfd, 10) != -1);

  while(1) {
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int clientfd = accept(sockfd, (struct sockaddr*) &client_addr, &client_len);
    printf("port=%d addr=%x\n", client_addr.sin_port, client_addr.sin_addr.s_addr);

  }
}