#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dpi.h"

#include <QMessageBox>

static dpi *xdpi = nullptr;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    qRegisterMetaType<QVector<ndpi_flow_info>>("QVector<ndpi_flow_info>");
    ui->setupUi(this);
    show_status_bar("waiting");

    model = new QStandardItemModel();
    model->setColumnCount(6);
    model->setHeaderData(0,Qt::Horizontal,"src_ip");
    model->setHeaderData(1,Qt::Horizontal,"src_port");
    model->setHeaderData(2,Qt::Horizontal,"dst_ip");
    model->setHeaderData(3,Qt::Horizontal,"dst_port");
    model->setHeaderData(4,Qt::Horizontal,"l4_protocol");
    model->setHeaderData(5,Qt::Horizontal,"l7_protocol");
    ui->resultTable->setModel(model);
    ui->resultTable->update();
    ui->resultTable->horizontalHeader()->setStretchLastSection(true);
    ui->resultTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->resultTable->setColumnWidth(0,180);
    ui->resultTable->setColumnWidth(1,80);
    ui->resultTable->setColumnWidth(2,180);
    ui->resultTable->setColumnWidth(3,80);
    ui->resultTable->setColumnWidth(4,80);
    ui->resultTable->setColumnWidth(5,100);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startCapture_clicked()
{
    model->removeRows(0,model->rowCount());
    ui->resultTable->update();
    ui->count->display(QString::number(0));
    QString dev =ui->device->text();
    xdpi = new dpi(dev,this);
    xdpi->start();
}

void MainWindow::on_stopCapture_clicked()
{
    xdpi->stopCapture();
}

void MainWindow::show_get_flow(struct ndpi_flow_info *flow){
//    ui->device->setText(ip);
   int count = model->rowCount();
   model->setItem(count,0,new QStandardItem(flow->src_name));
   model->setItem(count,1,new QStandardItem(QString::number(htons(flow->src_port))));
   model->setItem(count,2,new QStandardItem(flow->dst_name));
   model->setItem(count,3,new QStandardItem(QString::number(htons(flow->dst_port))));
   model->setItem(count,4,new QStandardItem(QString::number(flow->protocol)));
   model->setItem(count,5,new QStandardItem(flow->protocol_name));
   free(flow);
   ui->resultTable->update();
   ui->resultTable->scrollToBottom();
}

void MainWindow::show_status_bar(QString status){
    QString prefix = "Status: ";
    ui->statusBar->showMessage(prefix + status);
}

void MainWindow::show_packet_count(long count){
    ui->count->display(QString::number(count));
}
