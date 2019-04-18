#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QStandardItemModel>
#include <QMainWindow>
#include "xdpi.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void show_get_flow(struct ndpi_flow_info *flow);
    void show_packet_count(long count);
    void show_status_bar(QString status);

private slots:
    void on_startCapture_clicked();
    void on_stopCapture_clicked();

private:
    Ui::MainWindow *ui;
    QStandardItemModel *model;
};

#endif // MAINWINDOW_H
