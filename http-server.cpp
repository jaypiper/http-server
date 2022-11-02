#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>

using namespace std;

#define HPPTPORT 80
#define BUFSZ 4096
#define METHODSZ 128
#define FILENAMESZ 256
#define LINELEN 1024
#define SHORTSZ 128

typedef struct HTTPMsg{
  int status;
  string status_msg;
  int length;
  vector<string> header;
  string body;
}HttpMsg;

string makeHttpResponse(HttpMsg* msg) {
  string response = "HTTP/1.1";
  response += " " + to_string(msg->status) + " " + msg->status_msg + "\r\n";
  response += "content-length: " + to_string(msg->body.length()) + "\r\n";
  for(int i = 0; i < msg->header.size(); i++) {
    response += msg->header[i] + "\r\n";
  }
  response += "\r\n" + msg->body;
  return response;
}

void requestHttp(int sockfd) {
  char buf[BUFSZ];
  read(sockfd, buf, BUFSZ);
  std::cout << buf<<std::endl;

  string buf_str = buf;
  assert(buf_str.find("HTTP/") != string::npos);
  int pos_start = 0, pos_end = 0;
  assert((pos_end = buf_str.find(" /")) != string::npos);
  string method = buf_str.substr(pos_start, pos_end-pos_start);

  pos_start = pos_end += 2;
  assert((pos_end = buf_str.find(" ", pos_start)) != string::npos);
  string filename = buf_str.substr(pos_start, pos_end-pos_start);

  assert((pos_start = buf_str.find("Host: ")) != string::npos);
  pos_start += 6;
  assert((pos_end = buf_str.find("\r", pos_start)) != string::npos);
  string host = buf_str.substr(pos_start, pos_end-pos_start);

  if(method == "GET") {
    HttpMsg msg = {.status = 301, .status_msg = "Moved Permanently"};
    msg.header.push_back("Location: https://" + host + "/" + filename);
    string http_resp = makeHttpResponse(&msg);
    std::cout <<"(" << http_resp << ")\n";
    send(sockfd, http_resp.c_str(), http_resp.length(), 0);

  }
}

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
    assert(clientfd != -1);
    requestHttp(clientfd);
  }
}