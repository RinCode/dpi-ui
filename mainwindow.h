#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void get_show();

private slots:
    void on_startCapture_clicked();

    void on_stopCapture_clicked();

private:
    Ui::MainWindow *ui;
    int count;
};

#endif // MAINWINDOW_H
