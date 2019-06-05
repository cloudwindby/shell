#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <Dbghelp.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //设置接收拖拽
    setAcceptDrops(true);
    //设置主窗口只有关闭按钮
    setWindowFlags(Qt::WindowCloseButtonHint);
    this->resize( QSize( 440, 400 ));
    m_WindowTitel = "CompressShell";
    setWindowTitle(m_WindowTitel);
}



MainWindow::~MainWindow()
{
    if(m_ucShellCodeBuffer != nullptr)
    {
        delete[] m_ucShellCodeBuffer;
        m_ucShellCodeBuffer = nullptr;
    }

    if(m_pNewPEHdr != nullptr)
    {
        delete[] m_pNewPEHdr;
        m_pNewPEHdr = nullptr;
    }

    if(m_pSecData != nullptr)
    {
        delete[] m_pSecData;
        m_pSecData = nullptr;
    }

    delete ui;
}

//重写拖拽
void MainWindow::dragEnterEvent(QDragEnterEvent *e)
{
    e->acceptProposedAction();
}

//重写拖拽
void MainWindow::dropEvent(QDropEvent *e)
{
    ClearInfo();
    //获取拖拽文件的路径
    QList<QUrl> urls = e->mimeData()->urls();

    if(urls.isEmpty())
        return;

    //获取文件名
    m_FileName = urls.first().toLocalFile();
    if(!m_FileName.isNull())
    {
        if(HandleFile())
        {
            AnalysePEFile();

        }
    }
}

bool MainWindow::HandleFile()
{
    m_OriginalFile.setFileName(m_FileName);
    //读写方式打开
    if(!m_OriginalFile.open(QIODevice::ReadWrite))
    {
        ui->FILE_PATH_EDIT->setText("文件打开失败");
        ClearInfo();
        return false;
    }
    else
    {
        QFileInfo info(m_OriginalFile);
        m_BaseFileName = info.baseName();
        //设置窗口标题
        setWindowTitle(m_WindowTitel + "  ---->  " + info.fileName());
        //文件路径
        ui->FILE_PATH_EDIT->setText(info.filePath());
        //文件大小
        ui->FILE_SIZE_EDIT->setText(QString::number(info.size()) + (" 字节"));
        //文件创建时间
        ui->FILE_CREATETIME_EDIT->setText(info.birthTime().toString("yyyy-MM-dd hh:mm:ss"));
        m_OriginalFileMapBuffer = m_OriginalFile.map(0,m_OriginalFile.size());
        if(nullptr == m_OriginalFileMapBuffer)
        {
            return false;
        }
        //判断是否是PE文件
        if(*m_OriginalFileMapBuffer == 0x4d && *(m_OriginalFileMapBuffer + 1) == 0x5a)
        {
            return true;
        }
        else
        {
            ui->FILE_TYPE_EDIT->setText("当前可能不是PE文件!");
            return false;
        }
    }
}

bool MainWindow::AnalysePEFile()
{
    AnalysePE Analyse(m_OriginalFileMapBuffer);

    m_pDosHdr = Analyse.pDOSHeader();
    m_pNtHdr = Analyse.pNTHeader();
    m_pFileHdr = Analyse.pFileHeader();
    m_pOptHdr = Analyse.pOptionalHeader();
    m_pSectHdr = Analyse.pSectionHeader();
    m_PEHeaderSize = m_pOptHdr->SizeOfHeaders;
    m_PEDataSize = m_OriginalFile.size() - m_PEHeaderSize;

    ImportOffset = m_pOptHdr->DataDirectory[1].VirtualAddress;
    ImportSize = m_pOptHdr->DataDirectory[1].Size;
    IATOffset = m_pOptHdr->DataDirectory[12].VirtualAddress;
    IATSize =  m_pOptHdr->DataDirectory[12].Size;
    m_pDosHdr->e_minalloc = LOWORD(ImportOffset);
    m_pDosHdr->e_maxalloc = HIWORD(ImportOffset);
    m_pDosHdr->e_ip = LOWORD(IATOffset);
    m_pDosHdr->e_cs = HIWORD(IATOffset);

    DWORD pdwImport = (DWORD)m_pDosHdr->e_minalloc;
    qDebug("ImportOffset:%p",ImportOffset);
    qDebug("pdwImport:%p",pdwImport);


    //    DWORD ImportFOA = (DWORD)ImageRvaToVa(m_pNtHdr,(PVOID)0,IATOffset,NULL);
    //    PIMAGE_IMPORT_DESCRIPTOR       pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(m_OriginalFileMapBuffer + ImportFOA);
    //    qDebug() << pImportTable;

    //    DWORD dwImportCount = 0;
    //    while(pImportTable[dwImportCount].Name)
    //    {

    //        DWORD DllNameOffset = (DWORD)(ImageRvaToVa(m_pNtHdr, (PVOID)0,pImportTable[dwImportCount].Name,NULL));
    //        qDebug("DLLName:%s", (LPCSTR)(m_OriginalFileMapBuffer + DllNameOffset));
    //        DWORD IATs = pImportTable[dwImportCount].FirstThunk;
    //        DWORD INTs = pImportTable[dwImportCount].OriginalFirstThunk;
    //        HMODULE h = LoadLibraryA((LPCSTR)m_OriginalFileMapBuffer + DllNameOffset);
    //         qDebug("HMODULE:%p",h);

    //        PIMAGE_THUNK_DATA pIAT_FA = (PIMAGE_THUNK_DATA)(m_OriginalFileMapBuffer + (DWORD)(ImageRvaToVa(m_pNtHdr, (PVOID)0,IATs,NULL)));
    //        PIMAGE_THUNK_DATA pINT_FA = (PIMAGE_THUNK_DATA)(m_OriginalFileMapBuffer + (DWORD)(ImageRvaToVa(m_pNtHdr, (PVOID)0,INTs,NULL)));
    //        int i = 0;
    //        while (pIAT_FA[i].u1.AddressOfData)
    //        {
    //            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(m_OriginalFileMapBuffer + (DWORD)ImageRvaToVa(m_pNtHdr, (PVOID)0,pINT_FA[i].u1.AddressOfData,NULL));
    ////            HANDLE addr = GetProcAddress(h,pImportByName->Name);
    ////            qDebug("Name:%s Addr:%p\n", pImportByName->Name, pIAT_FA[i].u1.Function);
    ////            qDebug("FuncAddr:%p\n",addr);
    ////            qDebug("FuncOffset:%p\n",(DWORD)addr - (DWORD)h);
    //            i++;
    //        }
    //        dwImportCount++;
    //    }
    //qDebug() << "dwImportCount:" << dwImportCount;

    qDebug("m_PEDataSize:%p",m_PEDataSize);
    WORD wMachine = m_pFileHdr->Machine;
    qDebug("Machine:%p",wMachine);

    switch (wMachine)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        ui->FILE_TYPE_EDIT->setText("Machine Unknown");
        break;
    case IMAGE_FILE_MACHINE_I386:
        ui->FILE_TYPE_EDIT->setText("Intel 386");
        break;
    case IMAGE_FILE_MACHINE_ALPHA:
        ui->FILE_TYPE_EDIT->setText("Alpha_AXP");
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        ui->FILE_TYPE_EDIT->setText("IBM PowerPC Little-Endian");
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        ui->FILE_TYPE_EDIT->setText("AMD64 (K8)");
        break;
    }

    return true;
}

DWORD MainWindow::GetAlignValue(DWORD dwAlign, DWORD dwValue)
{
    if (dwValue % dwAlign == 0)
    {
        return dwValue;
    }
    else
    {
        return (dwValue / dwAlign + 1) * dwAlign;
    }

    return 0;
}

bool MainWindow::MyEncrypt(unsigned char* src,unsigned char* dst,size_t size,DWORD key)
{
    qDebug("m_PEHeaderSize:%p",size);
    qDebug("KEY:%p",key);
    for(size_t i = 0;i < size;i++)
    {
        *dst =  *src ^ key;
        dst++;
        src++;
    }

    return true;
}


//bool MainWindow::GetSecData()
//{
//    //申请节区数据所需要的内存
//    m_dwSecDataSize = GetAlignValue(m_pOptHdr->FileAlignment, m_dwShellCodeSize); //对齐
//    m_pSecData = new BYTE[m_dwSecDataSize];

//    memcpy(m_pSecData,m_ucShellCodeBuffer, m_dwSecDataSize); //拷贝压缩数据
//    return false;
//}

bool MainWindow::GetNewSecHders()
{
    // 构建空节
    strcpy((char*)m_hdrNewSecs[SEC_SPACE].Name, ".text");
    m_hdrNewSecs[SEC_SPACE].Misc.VirtualSize = m_pOptHdr->SizeOfImage;
    m_hdrNewSecs[SEC_SPACE].VirtualAddress = m_pSectHdr->VirtualAddress;
    m_hdrNewSecs[SEC_SPACE].PointerToRawData = 0;
    m_hdrNewSecs[SEC_SPACE].SizeOfRawData = 0;
    m_hdrNewSecs[SEC_SPACE].Characteristics = 0xE0000040;

    // 构建PE头
    strcpy((char*)m_hdrNewSecs[SEC_PEHEADER].Name, ".rdata");
    m_hdrNewSecs[SEC_PEHEADER].Misc.VirtualSize = m_PEHeaderSize;
    m_hdrNewSecs[SEC_PEHEADER].VirtualAddress = m_hdrNewSecs[SEC_SPACE].VirtualAddress + m_hdrNewSecs[SEC_SPACE].Misc.VirtualSize;
    m_hdrNewSecs[SEC_PEHEADER].PointerToRawData = m_pOptHdr->SizeOfHeaders;
    m_hdrNewSecs[SEC_PEHEADER].SizeOfRawData = m_PEHeaderSize;
    m_hdrNewSecs[SEC_PEHEADER].Characteristics = 0xE0000040;

    // 构建PE数据节
    strcpy((char*)m_hdrNewSecs[SEC_PEDATA].Name, ".data");
    m_hdrNewSecs[SEC_PEDATA].Misc.VirtualSize = GetAlignValue(m_pOptHdr->SectionAlignment, m_PEDataSize);
    m_hdrNewSecs[SEC_PEDATA].VirtualAddress = GetAlignValue(m_pOptHdr->SectionAlignment,m_hdrNewSecs[SEC_PEHEADER].VirtualAddress + m_hdrNewSecs[SEC_PEHEADER].Misc.VirtualSize);
    m_hdrNewSecs[SEC_PEDATA].PointerToRawData = m_pOptHdr->SizeOfHeaders + m_PEHeaderSize;
    m_hdrNewSecs[SEC_PEDATA].SizeOfRawData = m_PEDataSize;
    m_hdrNewSecs[SEC_PEDATA].Characteristics = 0xE0000040;

    // 构建shellcode节
    strcpy((char*)m_hdrNewSecs[SEC_SHELLCODE].Name, ".code");
    m_hdrNewSecs[SEC_SHELLCODE].Misc.VirtualSize = GetAlignValue(m_pOptHdr->SectionAlignment, m_dwShellCodeSize);
    m_hdrNewSecs[SEC_SHELLCODE].VirtualAddress = GetAlignValue(m_pOptHdr->SectionAlignment,m_hdrNewSecs[SEC_PEDATA].VirtualAddress + m_hdrNewSecs[SEC_PEDATA].Misc.VirtualSize);
    m_hdrNewSecs[SEC_SHELLCODE].PointerToRawData = m_pOptHdr->SizeOfHeaders + m_PEHeaderSize +  m_PEDataSize;
    m_hdrNewSecs[SEC_SHELLCODE].SizeOfRawData = m_dwShellCodeSize;
    m_hdrNewSecs[SEC_SHELLCODE].Characteristics = 0xE0000040;

    return false;
}

bool MainWindow::GetNewPeHdr()
{
    //申请内存，存放新的PE头
    m_dwNewPEHdrSize = m_pOptHdr->SizeOfHeaders;
    m_pNewPEHdr = new BYTE[m_dwNewPEHdrSize];

    //拷贝原来的PE头

    memcpy(m_pNewPEHdr, m_OriginalFileMapBuffer, m_dwNewPEHdrSize);

    //解析PE头
    AnalysePE Analyse(m_pNewPEHdr);

    //修改头部
    Analyse.pFileHeader()->NumberOfSections = SEC_NUMBERS;
    Analyse.pOptionalHeader()->AddressOfEntryPoint = m_hdrNewSecs[SEC_SHELLCODE].VirtualAddress + m_dwEntryPointOffsetSection;
    Analyse.pOptionalHeader()->SizeOfImage = m_hdrNewSecs[SEC_SHELLCODE].VirtualAddress + m_hdrNewSecs[SEC_SHELLCODE].Misc.VirtualSize;
    qDebug("TotalSize:%d",Analyse.pOptionalHeader()->SizeOfImage);
    Analyse.pOptionalHeader()->DataDirectory[0].VirtualAddress = 0;
    Analyse.pOptionalHeader()->DataDirectory[0].Size = 0;
    Analyse.pOptionalHeader()->DataDirectory[1].VirtualAddress = 0;
    Analyse.pOptionalHeader()->DataDirectory[1].Size = 0;
    Analyse.pOptionalHeader()->DataDirectory[2].VirtualAddress = 0;
    Analyse.pOptionalHeader()->DataDirectory[2].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[3].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[3].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[4].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[4].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[5].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[5].Size = 0;
    Analyse.pOptionalHeader()->DataDirectory[6].VirtualAddress = 0;
    Analyse.pOptionalHeader()->DataDirectory[6].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[7].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[7].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[8].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[8].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[9].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[9].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[10].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[10].Size = 0;
//    Analyse.pOptionalHeader()->DataDirectory[11].VirtualAddress = 0;
//    Analyse.pOptionalHeader()->DataDirectory[11].Size = 0;
    Analyse.pOptionalHeader()->DataDirectory[12].VirtualAddress = 0;
    Analyse.pOptionalHeader()->DataDirectory[12].Size = 0;
    memcpy(Analyse.pSectionHeader(), m_hdrNewSecs, sizeof(m_hdrNewSecs)); //拷贝节表

    return true;
}

void MainWindow::ClearInfo()
{
    ui->FILE_CREATETIME_EDIT->clear();
    ui->FILE_PATH_EDIT->clear();
    ui->FILE_SIZE_EDIT->clear();
    ui->FILE_TYPE_EDIT->clear();
}

bool MainWindow::FileMap(QString& FileName)
{

    m_ShellCodeFile.setFileName(FileName);
    //读写方式打开
    if(!m_ShellCodeFile.open(QIODevice::ReadWrite))
    {
        return false;
    }
    else
    {
        return true;
    }
}

void MainWindow::on_GET_SHELLCODE_BUTTON_clicked()
{
    QString filename = QFileDialog::getOpenFileName();
    uchar* ShellCodeFileMapBuffer = nullptr;
    qDebug() << "FileName" << filename;
    if(!filename.isNull())
    {
        if(FileMap(filename))
        {
            ShellCodeFileMapBuffer = m_ShellCodeFile.map(0,m_ShellCodeFile.size());
        }

        qDebug("ShellCodeFileMapBuffer:%p",ShellCodeFileMapBuffer);
        if(ShellCodeFileMapBuffer != nullptr)
        {
            AnalysePE Analyse(ShellCodeFileMapBuffer);
            //ShellCode的代码在第一个节.所以只需要拷贝第一个节的节数据
            m_dwShellCodeSize = Analyse.pSectionHeader()[0].SizeOfRawData;
            qDebug("ShellCodeSize:%p",m_dwShellCodeSize);
            m_ucShellCodeBuffer = new BYTE[m_dwShellCodeSize];
            qDebug("ShellCodeBuffer:%p",m_ucShellCodeBuffer);
            memcpy(m_ucShellCodeBuffer, ShellCodeFileMapBuffer + Analyse.pSectionHeader()[0].PointerToRawData, m_dwShellCodeSize);
            m_dwEntryPointOffsetSection = Analyse.pOptionalHeader()->AddressOfEntryPoint - Analyse.pSectionHeader()[0].VirtualAddress;
            qDebug("EntryPointOffsetSection:%p",m_dwEntryPointOffsetSection);

        }
    }
}

void MainWindow::on_MAKE_SHELL_BUTTON_clicked()
{
    QString filename = QFileDialog::getSaveFileName(this, tr("Save File"),m_BaseFileName + "_packed.exe","*.*");
    if(!filename.isNull())
    {
        QFile SaveFile(filename);
        if(SaveFile.open(QIODevice::ReadWrite))
        {
            //4. 加密数据
            //GetCompressData();

            m_SecDataBuffer = new BYTE[m_PEDataSize];
            m_PeHeaderBuffer = new BYTE[m_PEHeaderSize];
            m_pOptHdr->DataDirectory[1].VirtualAddress = 0;
            m_pOptHdr->DataDirectory[1].Size = 0;
            m_pOptHdr->DataDirectory[12].VirtualAddress = 0;
            m_pOptHdr->DataDirectory[12].Size = 0;
            MyEncrypt(m_OriginalFileMapBuffer,m_PeHeaderBuffer,m_PEHeaderSize,PEKEY);
            MyEncrypt(m_OriginalFileMapBuffer + m_PEHeaderSize,m_SecDataBuffer,m_PEDataSize,DATAKEY);

            //恢复原始的数据
            m_pOptHdr->DataDirectory[1].VirtualAddress = ImportOffset;
            m_pOptHdr->DataDirectory[1].Size = ImportSize;
            m_pOptHdr->DataDirectory[12].VirtualAddress = IATOffset;
            m_pOptHdr->DataDirectory[12].Size = IATSize;
            //5. 生成新的EXE
            //1) 获取节数据
            //GetSecData();
            GetNewSecHders();
            //2) 获取新的头部
            GetNewPeHdr();
            //SaveFile.write((const char*)m_PEHeaderBuffer,m_PEHeaderSize);
            SaveFile.write((const char*)m_pNewPEHdr,m_dwNewPEHdrSize);
            SaveFile.seek(m_dwNewPEHdrSize);
            SaveFile.write((const char*)m_PeHeaderBuffer,m_PEHeaderSize);
            SaveFile.seek(m_dwNewPEHdrSize + m_PEHeaderSize);
            SaveFile.write((const char*)m_SecDataBuffer,m_PEDataSize);
            SaveFile.seek(m_dwNewPEHdrSize + m_PEHeaderSize + m_PEDataSize);
            SaveFile.write((const char*)m_ucShellCodeBuffer,m_dwShellCodeSize);
            qDebug("Size:%d",m_dwNewPEHdrSize+m_PEHeaderSize+m_PEDataSize+m_dwShellCodeSize);
        }
    }
}
