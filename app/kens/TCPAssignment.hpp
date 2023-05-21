/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_PAYLOAD 1440        //MSS= 1460, TCP header= 20 -> payload= 1440
#define WIN_SIZE 30000          //define size of receive window for receive buffer
#define RW_BUFF_SIZE 1000005

namespace E {

typedef std::pair<uint16_t, uint32_t> pi;
typedef std::pair<int, int> pf;
typedef std::pair<UUID, pf> upf;


struct RWcall{        
  UUID syscallUUID;
  int pid;
  int fd;
  int count;
  void* buffer; 
  RWcall(UUID syscallUUID, int pid, int fd, int count, void* buffer) 
    :syscallUUID(syscallUUID), pid(pid), fd(fd), count(count), buffer(buffer){}
};

struct ReceiveWindow {
  uint32_t NXT = 0;
  uint32_t WND = WIN_SIZE;
  ReceiveWindow() {}
};

struct SendWindow {
  uint32_t UNA = 0;
  uint32_t WND = WIN_SIZE;
  uint32_t NXT = 0;
  SendWindow() {}

  uint32_t getAvailableSpace() {
    return UNA + WND - NXT;
  }
};



enum SocketState{
  CLOSED,
  LISTEN,
  SYN_SENT,
  ESTABLISHED,
  CLOSE_WAIT,
  CLOSING,
  FIN_WAIT_1,
  FIN_WAIT_2,
  TIME_WAIT,
  LAST_ACK,
};

struct Socket {

  uint16_t local_port;
  uint16_t remote_port;

  uint32_t local_ip;
  uint32_t remote_ip;

  uint32_t local_seq;
  uint32_t remote_seq;

  uint16_t window_size = 51200;

  int backlog;

  UUID timerUUID;

  SocketState cur_state = CLOSED;

  ReceiveWindow rcvWnd = ReceiveWindow();
  SendWindow sendWnd = SendWindow();  

  char rcvBuffer[RW_BUFF_SIZE];
  char sendBuffer[RW_BUFF_SIZE];
  size_t sendBuffer_size= 0;

 

  std::vector<RWcall> blocked_read;
  std::vector<RWcall> blocked_write;

  Socket() {
    local_port = remote_port = -1;
    local_ip = remote_ip = -1;
    local_seq = remote_seq = -1;
    memset(rcvBuffer, 0, sizeof(rcvBuffer));
    memset(sendBuffer, 0, RW_BUFF_SIZE);
  }

};


class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  std::map<pf, Socket> listen_sockets;
  std::map<pf, Socket> established_sockets;
  std::map<pi, pf> bound_sockets;
  std::map<pf, std::map<pi, Socket>> syn_wait;
  std::map<pf, std::queue<Socket>> accept_queue;
  std::vector<upf> blocked_accepts;
  std::map<pi, Socket> connection_sockets;


public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
  virtual void syscall_close(UUID syscallUUID, int pid, int socket_fd);
  virtual void syscall_bind(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t addr_len);
  virtual void syscall_listen(UUID syscallUUID, int pid, int socket_fd, int backlog);
  virtual void syscall_connect(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t addr_len);
  virtual void syscall_accept(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len);
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len);
  virtual void syscall_getpeername(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len);
  virtual void syscall_read(UUID syscallUUID, int pid, int socket_fd,void *buffer, size_t count); 
  virtual void syscall_write(UUID syscallUUID, int pid, int socket_fd, void *buffer, size_t count);
  virtual void find_and_accept(pf pid_fd);
  virtual void close_helper(pf pid_fd);
  virtual void find_and_read(Socket& socket);
  virtual void find_and_write(Socket& socket); 
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual Packet preparePacket(Socket socket, bool ACK, bool SYN, bool FIN, uint32_t data_size);
  virtual void addCheckSumToPacket(Packet& packet);
  virtual void send_packet(Packet packet);
};  

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
