#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QFile>
#include <QUrl>
#include <QFileInfo>
#include <QFileDialog>
#include <QDateTime>
#include <QDebug>
#include <vector>
#include "common.h"
#include "analysepe.h"

#pragma comment(lib,"Dbghelp")

using namespace std;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

    struct  ConfigInfo
    {
        DWORD m_dwComDataOffset;
        DWORD m_dwComDataSize;
        DWORD m_dwDecomDataSize;
    };
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    virtual void dragEnterEvent(QDragEnterEvent *e);
    virtual void dropEvent(QDropEvent *e);

    void ClearInfo();
    bool FileMap(QString&);

private slots:
    void on_GET_SHELLCODE_BUTTON_clicked();

    void on_MAKE_SHELL_BUTTON_clicked();

private:
    Ui::MainWindow *ui;

    QString m_WindowTitel;

    /*
     *原始文件相关
     */
    QString m_FileName;
    QString m_BaseFileName;
    QFile m_OriginalFile;
    uchar* m_OriginalFileMapBuffer = nullptr;
    bool HandleFile();
    bool AnalysePEFile();
    /*
         * PE头部数据相关
        */
    PIMAGE_DOS_HEADER m_pDosHdr;
    PIMAGE_NT_HEADERS m_pNtHdr;
    PIMAGE_FILE_HEADER m_pFileHdr;
    PIMAGE_OPTIONAL_HEADER m_pOptHdr;
    PIMAGE_SECTION_HEADER m_pSectHdr;
    DWORD m_PEHeaderSize;
    DWORD GetAlignValue(DWORD dwAlign, DWORD dwValue);
    DWORD ImportOffset;
    DWORD ImportSize;
    DWORD IATOffset;
    DWORD IATSize;

    /*
     * 加密数据
     */
    LPBYTE m_SecDataBuffer;
    LPBYTE m_PeHeaderBuffer;
    DWORD m_PEDataSize;
    bool MyEncrypt(unsigned char* src,unsigned char* dst,size_t size,DWORD key);

    vector<char*> m_Name;


    /*
    *  解压缩代码相关
    */
    QFile m_ShellCodeFile;
    uchar* m_ucShellCodeBuffer = nullptr;//解压缩代码缓冲区
    DWORD m_dwShellCodeSize; //缓冲区大小
    DWORD m_dwEntryPointOffsetSection;  //shellcode的入口点相对于节首地址的偏移

    /*
        * 节数据
        */
    LPBYTE m_pSecData = nullptr;
    DWORD m_dwSecDataSize;
    bool GetSecData();

    /*
        * 新节表
        */
    enum
    {
        SEC_SPACE,
        SEC_PEHEADER,
        SEC_PEDATA,
        SEC_SHELLCODE,
        SEC_NUMBERS
    };
    IMAGE_SECTION_HEADER m_hdrNewSecs[SEC_NUMBERS];
    bool GetNewSecHders();

    /*
         新的PE头
        */
    LPBYTE m_pNewPEHdr = nullptr;
    DWORD m_dwNewPEHdrSize;
    bool GetNewPeHdr();
};

#endif // MAINWINDOW_H
