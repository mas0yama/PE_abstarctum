
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

##### Optional Header
Еще один обязательный подзаголовок PE-файла. Хранит необходимую для загрузки информация. Имеет два формата PE32+ (64) и PE32. Отличаются размером самой структуры и типом данных некоторых полей: ImageBase, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit
```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
- **Magic** - сигнатура исполняемого файла. **0x10B** - PE32 exec; **0x20B** - PE32+ exec; **0x107** - ROM image.
- **MajorLinkerVersion, MinorLinkerVersion** - версия линкера
- **SizeOfCode** - размер (.text) секции (суммарных размер всех секций)
- **SizeOfInitializedData** - размер (.data) секции (суммарный размер всех секций)
- **SizeOfUnitializedData** - размер (.bss) секции (суммарный размер всех секций)
- **AddressOfEntryPoint** - RVA (relative virtual address) точки входа (файл загружен в память). Согласно документации - в исполняемых файлах - к адресу начала, для драйверов устройств - к функции инициализации. В DLL точка входа опциональна, и поле может быть установлено в 0.
- **BaseOfCode** - RVA начала секции code, когда файл загружен в память
- **BaseOfData** - (только в PE32) - RVA начала секции data, когда файл загружен в память.
- **ImageBase** - поле содержит предпочитаемый адрес первого байта исп.файла при загрузке в память (basea address). Значение кратно 64к. Ввиду защит типа ASLR, это поле почти не используется  и загрузчик PE выбирает неиспользованную область памяти для загрузки исп.файла.
- **SectionAlignment** - поле содержит RVA начала секций в виртуальной памяти.
- **FileAlignment** - смещение относительно файла начала секций в исполняемой файле.
- **MajorSubsytemVersion** и **MinorSubsystemVersion** - необходимая версия Windows
- **SizeOfImage** - размер исполняемого файла, включая все заголовки
- **SizeOfHeaders** - размер DOS-заглушки,NT хэдеров и секции хэдеров.
- **Checksum** - chesum
- **Subsystem** - поле, указывающее подсистему (CLI, GUI, Driver)
- **DLLCharacteristiscs** - некоторые характеристики исполняемого файла. Несмотря на DLL в названии, есть и в обычных исполняемых файлах.
- **SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit** 
- **LoaderFlags** - зарезервировано. Всегда 0
- **NumberOfRvaAndSizes** - Размер массива DataDirectory
- **DataDirectory** - массив структур **IMAGE_DATA_DIRECTORY**






####  Список использованной литературы
- https://0xrick.github.io/win-internals
- https://habr.com/ru/articles/98174/
- https://codeby.net/threads/0x01-issleduem-portable-executable-exe-fajl-format-pe-fajla.65415/
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format



