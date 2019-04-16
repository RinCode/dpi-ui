#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dpi.h"

#include <QMessageBox>

static dpi *xdpi = nullptr;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    count=0;
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startCapture_clicked()
{
    QString dev =ui->device->text();
    xdpi = new dpi(dev,this);
    xdpi->start();
}

void MainWindow::get_show(){
    count++;
    ui->device->setText(QString::number(count));
}

void MainWindow::on_stopCapture_clicked()
{
    count = 0;
    xdpi->stopCapture();
    xdpi->quit();
    xdpi->wait();
    free(xdpi);
}
