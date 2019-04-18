#ifndef DPI_H
#define DPI_H

#include <inttypes.h>
#include <pcap.h>
#include <QString>
#include <QDebug>
#include <QThread>
#include "mainwindow.h"
#include "xdpi.h"

class dpi : public QThread
{
    Q_OBJECT

signals:
    void status_bar(QString status);
    void get_flow(struct ndpi_flow_info *flow);
    void packet_count(long count);

public slots:
    void show_status_bar(QString status);
    void show_get_flow(struct ndpi_flow_info *flow);
    void show_packet_count(long count);

private:
    MainWindow *m_gui;
    pcap_t * handler;
    void extractFlow(struct result *result);

public:
    dpi(QString dev,MainWindow *gui);
    ~dpi();
    void stopCapture();

protected:
    void run();

};

#endif // DPI_H
