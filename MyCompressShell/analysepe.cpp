#include "analysepe.h"

AnalysePE::AnalysePE()
{

}

AnalysePE::~AnalysePE()
{

}

AnalysePE::AnalysePE(unsigned char* PEbuffer)
{
    m_pDOSHeader = (PIMAGE_DOS_HEADER)PEbuffer;
    m_pNTHeader = (PIMAGE_NT_HEADERS)(PEbuffer + m_pDOSHeader->e_lfanew);
    m_pFileHeader = &m_pNTHeader->FileHeader;
    m_pOptionalHeader = &m_pNTHeader->OptionalHeader;
    m_pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)m_pOptionalHeader + m_pFileHeader->SizeOfOptionalHeader);
}

PIMAGE_DOS_HEADER AnalysePE::pDOSHeader() const
{
    return m_pDOSHeader;
}

void AnalysePE::setPDOSHeader(const PIMAGE_DOS_HEADER &pDOSHeader)
{
    m_pDOSHeader = pDOSHeader;
}

PIMAGE_NT_HEADERS AnalysePE::pNTHeader() const
{
    return m_pNTHeader;
}

void AnalysePE::setPNTHeader(const PIMAGE_NT_HEADERS &pNTHeader)
{
    m_pNTHeader = pNTHeader;
}

PIMAGE_FILE_HEADER AnalysePE::pFileHeader() const
{
    return m_pFileHeader;
}

void AnalysePE::setPFileHeader(const PIMAGE_FILE_HEADER &pFileHeader)
{
    m_pFileHeader = pFileHeader;
}

PIMAGE_OPTIONAL_HEADER AnalysePE::pOptionalHeader() const
{
    return m_pOptionalHeader;
}

void AnalysePE::setPOptionalHeader(const PIMAGE_OPTIONAL_HEADER &pOptionalHeader)
{
    m_pOptionalHeader = pOptionalHeader;
}

PIMAGE_SECTION_HEADER AnalysePE::pSectionHeader() const
{
    return m_pSectionHeader;
}

void AnalysePE::setPSectionHeader(const PIMAGE_SECTION_HEADER &pSectionHeader)
{
    m_pSectionHeader = pSectionHeader;
}
