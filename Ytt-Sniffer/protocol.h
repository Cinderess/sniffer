#include <sys/types.h>
#include <netinet/in.h>


#define snapLen 1518

#define arpRequest 1
#define arpReply 2

#define ethernetHead 14
#define ethernetAddr 6

#define ipHead(packet) ((((struct ip *)(packet + ethernetHead)) -> ipHV & 0x0f) * 4)
#define ipAddr 4

#define tcpFIN 0x01
#define tcpSYN 0x02
#define tcpRST 0x04
#define tcpPSH 0x08
#define tcpACK 0x10
#define tcpURG 0x20
#define tcpECE 0x40
#define tcpCWR 0x80



struct ethernet
{
    u_char etherHostD[ethernetAddr];
    u_char etherHostS[ethernetAddr];
    u_short etherType;
};


struct ip
{
    u_char ipHV;
    u_char ipTos;
    u_short ipLen;
    u_short ipId;
    u_short ipOffset;
    u_char ipTtl;
    u_char ipProtocol;
    u_short ipCkSum;
    u_char ipS[ipAddr];
    u_char ipD[ipAddr];
};

struct tcp
{
    u_short tcpS;
    u_short tcpD;
    u_int tcpSeq;
    u_int tcpAck;
    u_char tcpHR;
    u_char tcpFlag;
    u_short tcpWin;
    u_short tcpCkSum;
    u_short tcpUrgP;
};

struct udp
{
    u_short udpS;
    u_short udpD;
    u_short udpLen;
    u_short udpCkSum;
};

struct arp
{
    u_short arpHardware;
    u_short arpProtocol;
    u_char arpMac;
    u_char arpIp;
    u_short arpOperation;
    u_char arpSM[ethernetAddr];
    u_char arpSI[ipAddr];
    u_char arpDM[ethernetAddr];
    u_char arpDI[ipAddr];
};

struct icmp
{
    u_char icmpType;
    u_char icmpCode;
    u_short icmpCkSum;
    u_short icmpFlag;
    u_short icmpSeq;
    u_int icmpTime;
};
