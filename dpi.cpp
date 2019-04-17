#include "dpi.h"

void pcap_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

dpi::dpi(QString dev,MainWindow *gui)
{
    m_gui = gui;
    connect(this,SIGNAL(get_packet()),this,SLOT(get_slot()));

    char errbuf[PCAP_ERRBUF_SIZE];
    if (dev.isEmpty()){
        dev = pcap_lookupdev(errbuf);
    }
    if((handler = pcap_open_live(dev.toStdString().data(),BUFSIZ,1,1000,errbuf))==nullptr){
        if((handler = pcap_open_offline(dev.toStdString().data(),errbuf))==nullptr){
            qDebug()<<"error";
            exit(0);
        }
    }
}

dpi::~dpi(){
}

void dpi::stopCapture(){
    pcap_breakloop(handler);
}

void dpi::run(){
    struct pcap_pkthdr header;
    const u_char *packet;
    initDetect(handler);
    while (1) {
        packet = pcap_next(handler,&header);
        if(packet==nullptr){
            break;
        }else{
            handlePacket(&header,packet);
            emit get_packet();
        }
    }
}

void dpi::get_slot(){
    m_gui->get_show();
}
