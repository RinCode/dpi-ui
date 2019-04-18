#include "dpi.h"

dpi::dpi(QString dev,MainWindow *gui)
{
    m_gui = gui;
    connect(this,SIGNAL(status_bar(QString)),this, SLOT(show_status_bar(QString)));
    connect(this,SIGNAL(get_flow(struct ndpi_flow_info*)),this,SLOT(show_get_flow(struct ndpi_flow_info*)));
    connect(this,SIGNAL(packet_count(long)),this, SLOT(show_packet_count(long)));

    QString status;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (dev.isEmpty()){
        dev = pcap_lookupdev(errbuf);
    }
    if((handler = pcap_open_live(dev.toStdString().data(),BUFSIZ,1,1000,errbuf))==nullptr){
        if((handler = pcap_open_offline(dev.toStdString().data(),errbuf))==nullptr){
            status = "can't open" + dev;
            emit status_bar(status);
            return;
        }
    }
    struct bpf_program fcode;
    if (pcap_compile(handler, &fcode, "pppoes and ip", 1, 0xFFFFFF00) < 0) {
        status = "failed to set bpf";
        emit status_bar(status);
        return;
    } else {
        if (pcap_setfilter(handler, &fcode) < 0) {
            status = "failed to set filter";
            emit status_bar(status);
            return;
        }
    }
    status = "capture on " + dev;
    emit status_bar(status);
}

dpi::~dpi(){
}

void dpi::stopCapture(){
    pcap_breakloop(handler);
    emit status_bar("stopped");
}

void dpi::run(){
    struct pcap_pkthdr header;
    const u_char *packet;
    initDetect(handler);
    int count=0;
    while (1) {
        packet = pcap_next(handler,&header);
        if(packet==nullptr){
            break;
        }else{
            struct result *res;
            res = (struct result*)malloc(sizeof(struct result));
            res->next = nullptr;
            handlePacket(&header,packet,res);
            if(res->next!=nullptr){
                extractFlow(res);
            }
            emit packet_count(++count);
        }
    }
}

void dpi::extractFlow(struct result *result){
    struct result *tmp;
    tmp = result->next;
    while(tmp){
        emit get_flow(tmp->flow);
        tmp = tmp->next;
    }
    free(tmp);
}

void dpi::show_status_bar(QString status){
    qDebug()<<"singal";
    m_gui->show_status_bar(status);
}

void dpi::show_get_flow(struct ndpi_flow_info *flow){
    m_gui->show_get_flow(flow);
}

void dpi::show_packet_count(long count){
    m_gui->show_packet_count(count);
}
