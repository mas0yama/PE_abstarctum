
## N
Состоит из
- Заголовки
- Секции
![[struct.png]]
Рис 1. Структура PE
## Headers
### I
#### 1. DOS header (0x00 - 0x3f)

64-байтовая структура в начале PE файла. Не обязательна для современных систем, но используется для обратной совместимости. 
```c
// IMAGE_DOS_HEADER struct from winnt.h
// typedef long LONG; signed 32bit int
// typedef unsigned short WORD; unsigned 16bit int
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER
```
Структура важна для загрузки на MS-DOS, но на **современных системах** используются только **два поля** : 

- **e_magic** - 2-байтовая сигнатура **0x5A4D** ("**MZ**")
- **e_lfanew** - последнее поле (оффест 0x3c) - адрес внутри файла на новый exe заголовок.

#### 2. MS-DOS STUB

Программа, при загрузке в MS-DOS выводит сообщение о несовместимости с DOS режимом.

#### 3. [Rich Header](https://habr.com/ru/articles/98174/)

Между  DOS-заглушкой и NT-заголовками расположена недокументированная структура, присутствующая только в исполняемых файлах, собранных инструментами Visual Studio. Структура содержит метаинформацию об инструментах для сборки, имена, типы, версии и номера билдов.

### II 
#### 1. NT Headers

```c
// IMAGE_NT_HEADERS struct from winnt.h
// typedef long LONG; signed 32bit int
// typedef unsigned short WORD; unsigned 16bit int
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

```
##### PE Signature
Поле, 4байтовое с фиксированным значением **0x50450000** ("**PE\\0\\0**")

##### File Header (COFF (common object file format) File header)
```c
// IMAGE_FILE_HEADER struct from winnt.h
// typedef long LONG; signed 32bit int
// typedef unsigned short WORD; unsigned 16bit int
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

```
- **[Machine](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)** - архитектура ЦП. 0x8664 - x64, 0x14c - i386/
- **NumberOfSections** - число секций (размер section table)
- **TimeDateStamp** - unix время создания файла.
- **PointerToSymbolTable** и **NumberOfSymbols** - поля с оффсетом до таблицы символов COFF и числом записей в этой таблице. Если нет дебаг инфы, то установлены в 0
- **SizeOfOptionalHeader** - размер Optional Header
- **[Charasteristics](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)** - флаги атрибутов файла. Например, исполняемый ли файл, системный и т.д.
![[characteristics.png]]
Рис 2 - пример содержимого поля Charasteristic (PE-bear, Obsidian MD)


####  Список использованной литературы
- https://0xrick.github.io/win-internals
- https://habr.com/ru/articles/98174/
- https://codeby.net/threads/0x01-issleduem-portable-executable-exe-fajl-format-pe-fajla.65415/
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
