#include "widget.h"
#include "ui_widget.h"
#include <QDebug>
#include <QPushButton>
#include <QTimer>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"
#define PROM 1
//promiscuous mode

char filter[128]; //过滤条件
char *dev; //抓包设备

int flowTotal = 0; //总流量计数
int ipv4Flow = 0, ipv6Flow = 0, arpFlow = 0;
int ipv4Cnt = 0, ipv6Cnt = 0, arpCnt = 0;
int tcpFlow = 0, udpFlow = 0, icmpFlow = 0;
int tcpCnt = 0, udpCnt = 0, icmpCnt = 0;
int otherCnt = 0, otherFlow = 0;

u_int id = 0;
//以太网解析
void ethernetAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    analyze analyze;
    Ui::Widget *ui = (Ui::Widget *)arg;

    struct ethernet *eHead;
    u_short protocol;
    char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    int flow = pcapPkt -> caplen;
    flowTotal += flow;

    printf("#########################################\n");
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("id: %d\n", ++id);
    printf("packet length: %d\n", flow);
    printf("receive time: %s\n", time);
    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString("数据包长度: %1").arg(flow) << QString::number(id));
    // treeWidget layout
    ui->treeWidget->addTopLevelItem(topInfo);

    char tmp[3] = {0};
    QString res;
    for(int i = 0; i < pcapPkt->len; i++)
    {
        printf("%02x ", packet[i]);
        sprintf(tmp, "%02x ", packet[i]);
        res += tmp;
        if((i+1) % 16 ==0)
        {
            printf("\n");
            sprintf(tmp, "\n");
            res += tmp;
        }
    }
    QTreeWidgetItem *pInfo = new QTreeWidgetItem(QStringList() << "数据包内容" << res);
    topInfo->addChild(pInfo);
    res.clear();

    printf("\n\n");

    eHead = (struct ethernet*)packet;
    printf("************ 数据链路层 ************\n");
    printf("~~~~~~~data link layer~~~~~~~\n");
    printf("Mac 源地址: ");
    res += "Mac 源地址: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
            res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
            res += tmp;
        }
    }
    printf("Mac 目的地址: ");
    res += "Mac 目的地址: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostD[i]);
            sprintf(tmp, "%02x\n", eHead -> etherHostD[i]);
            res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostD[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostD[i]);
            res += tmp;
        }
    }
    QTreeWidgetItem * linkInfo = new QTreeWidgetItem(QStringList() << "数据链路层" << res);
    topInfo->addChild(linkInfo);
    res.clear();

    protocol = ntohs(eHead -> etherType);

    QStringList resList;
    QTreeWidgetItem *netInfo, *transInfo;
    printf("************ 网络层 ************\n");
    printf("~~~~~~network layer~~~~~~\n");
    switch (protocol)
    {
    case 0x0800:
        printf("#######IPv4!\n");
        topInfo->setText(0,"IPV4");
        res += "IPv4\n";
        res += analyze.ipAnalyze(arg, pcapPkt, packet);


        resList = res.split('#');
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << resList[0]);
        topInfo->addChild(netInfo);
        transInfo = new QTreeWidgetItem(QStringList() << "传输层" << resList[1]);
        topInfo->addChild(transInfo);

        if (resList[1].contains("TCP",Qt::CaseSensitive)){
            topInfo->setText(0,"IPV4 TCP");
        }
        else if(resList[1].contains("UDP",Qt::CaseSensitive)){
            topInfo->setText(0,"IPV4 UDP");
        }
        else if(resList[1].contains("ICMP",Qt::CaseSensitive)){
            topInfo->setText(0,"IPV4 ICMP");
        }

        res.clear();
        resList.clear();
        ipv4Flow += flow;
        ipv4Cnt ++;
        break;
    case 0x0806:
        printf("#######ARP!\n");
        topInfo->setText(0,"ARP");
        res += "ARP\n";
        res += analyze.arpAnalyze(arg, pcapPkt, packet);
        arpFlow += flow;
        arpCnt ++;
        break;
    case 0x08DD:
        printf("#######IPv6!\n");
        topInfo->setText(0,"IPv6");
        res += "IPv6!\n";
        ipv6Flow += flow;
        ipv6Cnt ++;
        break;
    default:
        printf("Other network layer protocol!\n");
        topInfo->setText(0,"Other");
        res += "Other network layer protocol!\n";
        otherCnt ++;
        otherFlow += flow;
        break;
    }
    if(!res.isEmpty())
    {
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << res);
        topInfo->addChild(netInfo);
        res.clear();
    }

    printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
}


pcap_t *pcap;

//抓取数据包，传入抓取数量
void Widget::startSniffer(int num)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;


    //获取
    //ui->textBrowser->append("Finding deveice ......");
    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        printf("No device has been found! \n");
    }
    dev = allDev -> name;

    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Could not found netmask for device %s!\n", dev);
        net = 0;
        mask = 0;
    }

    QApplication::processEvents();

    //开始抓取
    QApplication::processEvents();
    pcap_loop(pcap, num, ethernetAnalyze, (u_char *) ui);

    //关闭设备
    pcap_close(pcap);
}


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);




    //开始嗅探
    connect(ui->startBtn, &QPushButton::clicked, this, [=](){
          startSniffer(300);
        QStringList cntList, flowList;
        cntList << QString::number(tcpCnt) << QString::number(udpCnt) << QString::number(arpCnt)  << QString::number(ipv4Cnt) << QString::number(ipv6Cnt) << QString::number(icmpCnt) ;
        flowList << QString::number(tcpFlow) << QString::number(udpFlow) << QString::number(arpFlow)  << QString::number(ipv4Flow) << QString::number(ipv6Flow) << QString::number(icmpFlow) ;

    });


    //tree widget
    ui->treeWidget->setHeaderLabels(QStringList() << "TYPE" << "ID");
    ui->treeWidget->setColumnWidth(0, 170);
}

Widget::~Widget()
{
    delete ui;
}

