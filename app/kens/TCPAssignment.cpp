/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  this->listen_sockets.clear();
  this->established_sockets.clear();
  this->bound_sockets.clear();
  this->syn_wait.clear();
  this->accept_queue.clear();
  this->blocked_accepts.clear();
}

void TCPAssignment::finalize() {}

void TCPAssignment::close_helper(E::pf pid_fd) {
  bool isInEstablish = this->established_sockets.count(pid_fd) != 0;
  Socket& socket = isInEstablish ? this->established_sockets[pid_fd] : this->listen_sockets[pid_fd];
  uint16_t local_port = socket.local_port;
  uint32_t local_ip = socket.local_ip;
  E::pi local_pi = {local_port, local_ip};

  this->listen_sockets.erase(pid_fd);
  this->established_sockets.erase(pid_fd);
  this->bound_sockets.erase(local_pi);
  this->syn_wait.erase(pid_fd);
  this->accept_queue.erase(pid_fd);
  SystemCallInterface::removeFileDescriptor(pid_fd.first, pid_fd.second);
  if(this->listen_sockets.count(pid_fd) != 0) {
    close_helper(pid_fd);
  }
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type) {
  //All sockets are AF_INET, SOCK_STREAM, and IPPROTO_TCP;
  Socket new_soc = Socket();
  new_soc.local_seq = rand();
  new_soc.sendWnd.UNA = new_soc.local_seq;
  new_soc.sendWnd.NXT = new_soc.sendWnd.UNA + 1;
  int new_fd = SystemCallInterface::createFileDescriptor(pid);
  this->listen_sockets[{pid, new_fd}] = new_soc;
  this->returnSystemCall(syscallUUID, new_fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket_fd) {
  E::pf pid_fd = {pid, socket_fd};
  if(this->listen_sockets.count(pid_fd) == 0 && this->established_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  bool isInEstablish = this->established_sockets.count(pid_fd) != 0;
  
  Socket& socket = isInEstablish ? this->established_sockets[pid_fd] : this->listen_sockets[pid_fd];

  SystemCallInterface::removeFileDescriptor(pid, socket_fd);

  if(isInEstablish && socket.cur_state == ESTABLISHED) {
    Packet finPacket = preparePacket(socket, false, false, true, 0);
    addCheckSumToPacket(finPacket);
    this->send_packet(finPacket);    
    close_helper(pid_fd);
  } else if(!isInEstablish) {
    close_helper(pid_fd);
  }

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int socket_fd, int backlog) {
  E::pf pid_fd = {pid, socket_fd};
  if(this->listen_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Socket& socket = this->listen_sockets[pid_fd];
  socket.cur_state = E::SocketState::LISTEN;
  socket.backlog = backlog;

  this->returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* sv_addr, socklen_t addr_len) {
  E::pf pid_fd = {pid, socket_fd};
  if(this->listen_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  uint16_t local_port = ntohs(((sockaddr_in*)sv_addr)->sin_port);
  uint32_t local_ip = ntohl(((sockaddr_in*)sv_addr)->sin_addr.s_addr);

  E::pi local_pi = {local_port, local_ip};
  E::pi local_pi_any = {local_port, INADDR_ANY};

  if((this->bound_sockets.count(local_pi) != 0 && this->bound_sockets[local_pi] != pid_fd)
    ||this->bound_sockets.count(local_pi_any) != 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->bound_sockets[local_pi] = pid_fd;
  Socket& socket = this->listen_sockets[pid_fd];
  socket.local_port = local_port;
  socket.local_ip = local_ip;
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t addr_len) {
  E::pf pid_fd = {pid, socket_fd};
  if(this->listen_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Socket& socket = this->listen_sockets[pid_fd];

  uint16_t remote_port = ntohs(((sockaddr_in*)socket_addr)->sin_port);
  uint32_t remote_ip = ntohl(((sockaddr_in*)socket_addr)->sin_addr.s_addr);

  E::pi remote_pi = {remote_port, remote_ip};

  std::pair<uint16_t, uint32_t> local_pi = {this->listen_sockets[pid_fd].local_port, this->listen_sockets[pid_fd].local_ip} ;

  uint32_t local_ip;
  uint16_t local_port;

  if(local_pi == std::pair<uint16_t, uint32_t>{(uint16_t)-1, (uint32_t)-1}) {
    ipv4_t ipv4_remote_ip = E::NetworkUtil::UINT64ToArray<4UL>(remote_ip);

    int NIC_port = getRoutingTable(ipv4_remote_ip);

    std::optional<ipv4_t> tmp_local_ip = getIPAddr(NIC_port);

    if(tmp_local_ip.has_value() == false) {
      returnSystemCall(syscallUUID, -1);
      return;
    }
    uint64_t ipp = NetworkUtil::arrayToUINT64(tmp_local_ip.value());
    local_ip = ntohl((uint32_t)ipp);    
    while(1){
      local_port= rand()%((2<<16 - 1)-1024) + 1024;
      if ((bound_sockets.count({local_port, local_ip}) ==0) || (bound_sockets.count({local_port, INADDR_ANY}) ==0)){
        break; 
      }
    }
  } else {
    local_ip = local_pi.second;
    local_port = local_pi.first;
  }

  this->bound_sockets[{local_port, local_ip}] = pid_fd;

  socket.local_ip = local_ip;
  socket.local_port = local_port;
  socket.remote_ip = remote_ip;
  socket.remote_port = remote_port;
  socket.remote_seq = 0;
  socket.cur_state = SYN_SENT;

  Packet synPacket = preparePacket(socket, false, true, false, 0);
  addCheckSumToPacket(synPacket);
  send_packet(synPacket);
  returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::find_and_accept(E::pf pid_fd) {
  for(int i = 0; i < blocked_accepts.size(); i++) {
    if(blocked_accepts[i].second == pid_fd) {
      UUID syscallUUID = blocked_accepts[i].first;
      Socket connect_socket = accept_queue[pid_fd].front();
      accept_queue[pid_fd].pop();
      int new_fd = SystemCallInterface::createFileDescriptor(pid_fd.first);
      blocked_accepts.erase(blocked_accepts.begin() + i);
      E::pf new_pid_fd = {pid_fd.first, new_fd};
      this->established_sockets[new_pid_fd] = connect_socket;
      this->returnSystemCall(syscallUUID, new_fd);
      return;
    }
  }
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len) {
  E::pf pid_fd = {pid, socket_fd};
  if(this->listen_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  blocked_accepts.push_back({syscallUUID, pid_fd});

  ((sockaddr_in*)socket_addr)->sin_family = AF_INET;

  if(accept_queue[pid_fd].size() == 0) {
    return;
  }

  Socket connect_socket = accept_queue[pid_fd].front();
  
  ((sockaddr_in*)socket_addr)->sin_addr.s_addr = htonl(connect_socket.remote_ip);
  ((sockaddr_in*)socket_addr)->sin_port = htons(connect_socket.remote_port);
  *addr_len = std::min(*addr_len, (socklen_t) sizeof(*socket_addr));

  find_and_accept(pid_fd);

}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len) {
  E::pf pid_fd = {pid, socket_fd};
  ((sockaddr_in*)socket_addr)->sin_family = AF_INET;  
  if(this->listen_sockets.count(pid_fd) == 0 && this->established_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  bool isInEstablish = this->established_sockets.count(pid_fd) != 0;

  Socket socket = isInEstablish ? this->established_sockets[pid_fd] : this->listen_sockets[pid_fd];

  
  ((sockaddr_in*)socket_addr)->sin_addr.s_addr = htonl(socket.local_ip);
  ((sockaddr_in*)socket_addr)->sin_port = htons(socket.local_port);

  *addr_len = std::min(*addr_len, (socklen_t) sizeof(socket_addr));

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int socket_fd, struct sockaddr* socket_addr, socklen_t* addr_len) {
  E::pf pid_fd = {pid, socket_fd};
  ((sockaddr_in*)socket_addr)->sin_family = AF_INET;
  if(this->established_sockets.count(pid_fd) == 0 && this->listen_sockets[pid_fd].cur_state != SYN_SENT) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  bool isInListen = this->listen_sockets.count(pid_fd) != 0;
  Socket& socket = this->established_sockets[pid_fd];
  if(isInListen) socket = this->listen_sockets[pid_fd];


  ((sockaddr_in*)socket_addr)->sin_addr.s_addr = htonl(socket.remote_ip);
  ((sockaddr_in*)socket_addr)->sin_port = htons(socket.remote_port);

  *addr_len = std::min(*addr_len, (socklen_t) sizeof(socket_addr));

  this->returnSystemCall(syscallUUID, 0);

}



void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int socket_fd, void *buffer, size_t count) {
  E::pf pid_fd = {pid, socket_fd};

  if(this->established_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Socket& socket = this->established_sockets[pid_fd];

  RWcall readCall = RWcall(syscallUUID, pid, socket_fd, count, buffer);

  socket.blocked_read.push_back(readCall);
  
  find_and_read(socket);
}

void TCPAssignment::find_and_read(Socket& socket) {
  
  std::vector<RWcall>& blocked_read = socket.blocked_read;

  while(blocked_read.size()) {
    RWcall curRead = blocked_read.front();
    UUID syscallUUID = curRead.syscallUUID;
    E::pf pid_fd = {curRead.pid, curRead.fd};
    uint32_t count = std::min(curRead.count, int(strlen(socket.rcvBuffer)));
    void* buffer = curRead.buffer;

    if(count != 0) {

      memcpy(buffer, socket.rcvBuffer, count);

      char* tmp;
      char* remainingStart = socket.rcvBuffer + count;
      int remainingLen = strlen(socket.rcvBuffer) - count;
      memcpy(tmp, remainingStart, remainingLen);
      memset(socket.rcvBuffer, 0, sizeof(socket.rcvBuffer));
      memcpy(socket.rcvBuffer, tmp, remainingLen);

      this->returnSystemCall(syscallUUID, count);     
      blocked_read.erase(blocked_read.begin());
    } else {
      break;
    }
  }
}








void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int socket_fd, void *buffer, size_t count) {
  E::pf pid_fd = {pid, socket_fd};

  if(this->established_sockets.count(pid_fd) == 0) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Socket& socket = this->established_sockets[pid_fd];

  SendWindow& sendWindow = socket.sendWnd;

  if(RW_BUFF_SIZE - socket.sendBuffer_size < count) {
    //not have enough space in the buffer
    this->returnSystemCall(syscallUUID, -1);
    return;
  }


  memcpy(socket.sendBuffer + socket.sendBuffer_size, buffer, count);

  socket.sendBuffer_size += count; 

  RWcall writeCall = RWcall(syscallUUID, pid, socket_fd, count, buffer);
  socket.blocked_write.push_back(writeCall);

  find_and_write(socket);

}

void TCPAssignment::find_and_write(Socket& socket) {
  
  std::vector<RWcall>& blocked_write = socket.blocked_write;

  SendWindow& sendWindow = socket.sendWnd;

  
  while(blocked_write.size()) {
    RWcall curWrite = blocked_write.front();
    UUID syscallUUID = curWrite.syscallUUID;
    E::pf pid_fd = {curWrite.pid, curWrite.fd};
    
    uint32_t count = curWrite.count > RW_BUFF_SIZE - socket.sendBuffer_size? RW_BUFF_SIZE - socket.sendBuffer_size : curWrite.count ;

    void* buffer = curWrite.buffer;
    if(count != 0 && sendWindow.getAvailableSpace() >= count) {
      
      Packet sendPacket = preparePacket(socket, true, false, false, count); //WARNING: this packet doesnt have data and checksum yet
      // At this line, NXT is not updated yet, so NXT - UNA - 1 is the relative position of the data to the start of the sendBuffer
      sendPacket.writeData(54, socket.sendBuffer + (sendWindow.NXT -1  - sendWindow.UNA), count); 
      // std::cout << "offset: "<< sendWindow.NXT -1  - sendWindow.UNA << std::endl;
      addCheckSumToPacket(sendPacket);
      send_packet(sendPacket);

      socket.sendWnd.NXT += count;
      std::cout << "nxt: "<< socket.sendWnd.NXT << std::endl;
      socket.local_seq += count;
      this->returnSystemCall(syscallUUID, count);
      blocked_write.erase(blocked_write.begin());
    } else {
      break;
    }
  }

}





Packet TCPAssignment::preparePacket(Socket socket, bool ACK, bool SYN, bool FIN, uint32_t data_size) {

  /*
    This function get {data_size} to create a packet with size of {54 + data_size} and fill with basic information (source and destination)
    The data is not written to the packet in this function yet, it will be written in the place in which this function is called
    if the {data_size} = 0, there is no need to write the data to the packet
    checksum is not calculated in this function due to the implemetation above, checksum will be calculated in the {addChecksumToPacket} function
  */
  
  uint16_t local_port = htons(socket.local_port);
  uint16_t remote_port = htons(socket.remote_port);
  uint16_t window_size = htons(socket.window_size);

  uint32_t local_ip = htonl(socket.local_ip);
  uint32_t remote_ip = htonl(socket.remote_ip);

  uint32_t local_seq = htonl(socket.local_seq);
  uint32_t remote_ack = htonl(socket.remote_seq + 1);

  uint8_t hl_4_bits = 5 << 4;
  uint8_t two_bits_and_flags = 0;
  if(ACK) two_bits_and_flags |= 16;
  if(SYN) two_bits_and_flags |= 2;
  if(FIN) two_bits_and_flags |= 1;

  uint16_t checksum = 0;
  uint16_t urgent = 0;

  Packet packet = Packet(54 + data_size);

  packet.writeData(14 + 12, &local_ip   , 4);
  packet.writeData(14 + 16, &remote_ip  , 4);
  packet.writeData(34     , &local_port , 2);
  packet.writeData(34 + 2 , &remote_port, 2);
  packet.writeData(34 + 4 , &local_seq, 4);
  packet.writeData(34 + 8 , &remote_ack, 4);
  packet.writeData(34 + 12, &hl_4_bits, 1);
  packet.writeData(34 + 13, &two_bits_and_flags, 1);
  packet.writeData(34 + 14, &window_size, 2);
  packet.writeData(34 + 16, &checksum, 2);
  packet.writeData(34 + 18, &urgent, 2);

  

  return packet;
}

void TCPAssignment::addCheckSumToPacket(Packet& packet) {

  uint32_t local_ip, remote_ip;

  packet.readData(14 + 12, &local_ip, 4);
  packet.readData(14 + 16, &remote_ip, 4);

  uint32_t data_size = packet.getSize() - 54;

  uint8_t tcp[20 + data_size];
  packet.readData(34, tcp, 20 + data_size);

  uint16_t checksum = htons((E::NetworkUtil::tcp_sum(local_ip, remote_ip, tcp, 20 + data_size)) ^ 0xFFFF);
  packet.writeData(34 + 16, &checksum, 2);

}

void TCPAssignment::send_packet(Packet packet) {
  this->sendPacket("IPv4", packet);
}


void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {

  size_t size = packet.getSize();
  int data_size = packet.getSize() - 54;
  uint32_t ACK, remote_seq, remote_ip, local_ip;
  uint16_t remote_port, local_port, header_checksum;
  uint16_t header;

  packet.readData(14 + 12, &remote_ip, 4);
  packet.readData(14 + 16, &local_ip, 4);

  packet.readData(34     , &remote_port, 2);
  packet.readData(34 +  2, &local_port, 2);
  packet.readData(34 +  4, &remote_seq, 4);  //read seq bytes of header
  packet.readData(34 +  8, &ACK, 4);
  packet.readData(34 + 13, &header, 1);
  header= ntohs(header);
  
  int FIN = (header & 1);
  
  int SYN = (header & 2) >> 1;
  
  uint8_t isACK = (header & 16) != 0 ? 1 : 0;
  local_port = ntohs(local_port);
  remote_port = ntohs(remote_port);
  remote_ip = ntohl(remote_ip);
  local_ip = ntohl(local_ip);
  remote_seq = ntohl(remote_seq);

  ACK = ntohl(ACK); 
  

  E::pi local_pi = {local_port, local_ip};
  E::pi local_pi_any = {local_port, INADDR_ANY};
  E::pi remote_pi = {remote_port, remote_ip};


  if(this->bound_sockets.count(local_pi) == 0 && this->bound_sockets.count(local_pi_any) == 0) {
    return;
  }

  E::pf pid_fd = (this->bound_sockets.count(local_pi) == 0) ? this->bound_sockets[local_pi_any] : this->bound_sockets[local_pi];

  if(FIN == 0) {
    if(SYN == 1) {
      if(this->listen_sockets.count(pid_fd) == 0) {
        return;
      }
      Socket socket = this->listen_sockets[pid_fd];
      std::map<E::pi, Socket>& syn_wait = this->syn_wait[pid_fd];
      std::queue<Socket>& accept_queue =  this->accept_queue[pid_fd];
      if(ACK == 0) {
        //this is the first received SYN
        if(syn_wait.size() == socket.backlog) {
          return;
        } 
        Socket temp;
        temp.local_ip = local_ip;
        temp.local_port = local_port;
        temp.remote_port = (socket.cur_state == SYN_SENT) ? socket.remote_port : remote_port;
        temp.remote_ip = (socket.cur_state == SYN_SENT) ? socket.remote_ip : remote_ip;
        temp.remote_seq = remote_seq;

        temp.rcvWnd.NXT = remote_seq;
        temp.sendWnd.UNA += 1;
        temp.sendWnd.NXT += 1;

        syn_wait[{temp.remote_port, temp.remote_ip}] = temp;
        Packet synPacket = preparePacket(temp, true, true, false, 0);
        addCheckSumToPacket(synPacket);
        this->send_packet(synPacket);
      } else {
        //this is client receive SYNACK 
        if(socket.cur_state == SYN_SENT && socket.remote_ip == remote_ip && socket.remote_port == remote_port) {
          Socket tmp = this->listen_sockets[pid_fd];
          tmp.remote_seq = remote_seq;
          tmp.local_seq++;
          tmp.cur_state = ESTABLISHED;

          tmp.rcvWnd.NXT = remote_seq;
          tmp.sendWnd.UNA += 1;
          tmp.sendWnd.NXT += 1;

          this->established_sockets[pid_fd] = tmp;
          this->connection_sockets[remote_pi] = tmp;
          Packet last_handshake_packet = preparePacket(tmp, true, false, false, 0);
          addCheckSumToPacket(last_handshake_packet);
          this->send_packet(last_handshake_packet);
        }
      }
    } else {
      if(this->connection_sockets.count(remote_pi) == 0) {
        std::map<E::pi, Socket>& syn_wait = this->syn_wait[pid_fd];
        std::queue<Socket>& accept_queue = this->accept_queue[pid_fd];
        if(syn_wait.size() != 0 && syn_wait.count(remote_pi) != 0) {
          //this is the last ACK of 3 way handshake
          Socket soc_to_accept = syn_wait[remote_pi];
          soc_to_accept.cur_state = ESTABLISHED;
          soc_to_accept.remote_seq = remote_seq;

          soc_to_accept.rcvWnd.NXT = remote_seq;
          soc_to_accept.sendWnd.UNA += 1;
          soc_to_accept.sendWnd.NXT += 1;

          syn_wait.erase(remote_pi);
          accept_queue.push(soc_to_accept);
          find_and_accept(pid_fd);
        }
      } else {
        //Normal packet or LAST ACK in closing
        //currently considering it is LAST ACK in closing
        Socket& established_socket = this->connection_sockets[remote_pi];
        if(E::pi(established_socket.local_port, established_socket.local_ip) != local_pi) {
          return;
        }

        established_socket.rcvWnd.NXT = remote_seq;
        SendWindow& sendWindow = established_socket.sendWnd;

        switch(established_socket.cur_state) {
          case CLOSING: {
            established_socket.cur_state = TIME_WAIT;
            break;
          }
          case FIN_WAIT_1: {
            established_socket.cur_state = FIN_WAIT_2;
            break;
          }
          case LAST_ACK: {
            established_socket.cur_state = CLOSED;
            break;
          }
          case ESTABLISHED: {
            std::cout <<ACK<< std::endl;
            //this is for writing side 
            if(ACK >= sendWindow.UNA && ACK < sendWindow.NXT) {
              char* tmp;
              char* remainingStart = established_socket.sendBuffer + ACK + 1 - sendWindow.UNA;
              int remainingLen = strlen(established_socket.sendBuffer) - (ACK + 1 - sendWindow.UNA);
              memcpy(tmp, remainingStart, remainingLen);
              memset(established_socket.sendBuffer, 0, sizeof(established_socket.sendBuffer));
              memcpy(established_socket.sendBuffer, tmp, remainingLen);
              sendWindow.UNA = ACK + 1;
              std::cout << sendWindow.UNA << std::endl;
              find_and_write(established_socket);
            } else {
              //ignore the out of order package
            }

            //this is for reading side
            if(remote_seq == established_socket.rcvWnd.NXT && data_size != 0) {
              char* payload;
              packet.readData(54, payload, data_size);
              int curBuffLen = strlen(established_socket.rcvBuffer);
              if(RW_BUFF_SIZE - curBuffLen >= data_size) {
                memcpy(established_socket.rcvBuffer + curBuffLen, payload, data_size);
                established_socket.remote_seq = remote_seq;
                established_socket.local_seq++;

                //TODO: sendACK
                Packet ackPacket = preparePacket(established_socket, true, false, false, 0);
                addCheckSumToPacket(ackPacket);
                send_packet(ackPacket);
              } else {
                //ignore;
              }
              
            } else {
              //ignore
            }


            break;
          }
          default:
            break;
        }
      }
    }
  } else {
    std::cout <<"recv fin"<<std::endl;
    //FIN = 1
    if(SYN == 0 && this->connection_sockets.count(remote_pi) != 0) {
      Socket& established_socket = this->connection_sockets[remote_pi];
      established_socket.rcvWnd.NXT = remote_seq;
      switch(established_socket.cur_state) {
        case ESTABLISHED: {
          established_socket.cur_state = CLOSE_WAIT;

          break;
        }
        case FIN_WAIT_1: {
          established_socket.cur_state = CLOSING;
          break;
        }
        case FIN_WAIT_2: {
          established_socket.cur_state = TIME_WAIT;
          break;
        }
        default:
          break;
      }
      std::cout <<"recv fin"<<std::endl;
      Packet finPacket = preparePacket(established_socket, true, false, false, 0);
      addCheckSumToPacket(finPacket);
      send_packet(finPacket);
    }
  }
  

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}
} // namespace E
