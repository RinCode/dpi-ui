#ifndef DPI_H
#define DPI_H

#include <inttypes.h>
#include <pcap.h>
#include <QString>
#include <QDebug>
#include <QThread>
#include "mainwindow.h"

class dpi : public QThread
{
    Q_OBJECT

signals:
    void get_packet();

public slots:
    void get_slot();

private:
    MainWindow *m_gui;
    pcap_t * handler;

public:
    dpi(QString dev,MainWindow *gui);
    ~dpi();
    void stopCapture();

protected:
    void run();

};

#endif // DPI_H
