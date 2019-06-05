#ifndef ANALYSEPE_H
#define ANALYSEPE_H
#include <windows.h>

class AnalysePE
{
public:
    AnalysePE();
    ~AnalysePE();

    AnalysePE(unsigned char*);

    PIMAGE_DOS_HEADER pDOSHeader() const;
    void setPDOSHeader(const PIMAGE_DOS_HEADER &pDOSHeader);

    PIMAGE_NT_HEADERS pNTHeader() const;
    void setPNTHeader(const PIMAGE_NT_HEADERS &pNTHeader);

    PIMAGE_FILE_HEADER pFileHeader() const;
    void setPFileHeader(const PIMAGE_FILE_HEADER &pFileHeader);

    PIMAGE_OPTIONAL_HEADER pOptionalHeader() const;
    void setPOptionalHeader(const PIMAGE_OPTIONAL_HEADER &pOptionalHeader);

    PIMAGE_SECTION_HEADER pSectionHeader() const;
    void setPSectionHeader(const PIMAGE_SECTION_HEADER &pSectionHeader);

private:
    PIMAGE_DOS_HEADER m_pDOSHeader;
    PIMAGE_NT_HEADERS m_pNTHeader;
    PIMAGE_FILE_HEADER m_pFileHeader;
    PIMAGE_OPTIONAL_HEADER m_pOptionalHeader;
    PIMAGE_SECTION_HEADER m_pSectionHeader;
};

#endif // ANALYSEPE_H
