# PE_file

# Cấu trúc tập tin PE

- PE là viết tắt của từ Portable Execuable, đây là định dạng tập tin cho các tập tin thực thi được sử dụng trong hệ điều hành Windows gồm có các tập tin có phần mở rộng .exe, .dll (Dynamic Link Libraries) Kernel module (.srv), .cpl (Control Panel Applications) và nhiều tập tin khác nữa.
- Tập tin PE là cấu trúc dữ liệu lưu trữ thông tin cần thiết để OS Loader (tạm dịch: bộ nạp hệ điều hành) có thể nạp tập tin thực thi đó vào bộ nhớ và thực thi tập tin đó.

# Tổng quan về cấu trúc

1. Tổng quan

- Tổng quan cấu trúc file PE bao gồm các thành phần như sau:
    - DOS Header
    - DOS Stub
    - NT Headers
        - PE Signature
        - File Header
        - Optional Header
    - section

1.1 DOS Header

- DOS Header bắt đầu bằng 1 cấu trúc gồm 64 bytes long, cấu trúc được biểu diễn dưới đây:

```C
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
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

## NOTE:
- Thực chất trong struct trên thì mình chỉ cần quan tâm đến 2 struct member đó là: 
    - e_magic (struct member đầu tiên nằm tại offset 0x00). Struct member này còn được gọi là ```magic number```, nơi mà nó chứa giá trị cố định là 0x5A4D (là 'MZ' trong bảng mã ASCII), đóng vai trò là 01 signature để chỉ ra rằng tập tin này chính là tập tin thực thi MS-DOS.
    - e_lfanew (struct member cuối cùng nằm tại offset 0x3c).

1.2 DOS Stub

- Là một chương trình MS-DOS có chức năng in nội dung: ```This program cannot be run in DOS mode.```. Ý nghĩa của nội dung này nói rằng chương trình đang thực thi này ```không tương thích``` với môi trường DOS và sẽ thoát chương trình. Chú ý đây là nội dung mặc định khi hiển thị lỗi trên và nó có thể thay đổi bởi người dùng trong quá trình biên dịch chương trình.

1.3 Rich Header

- Thực chất Rich Header ```không phải là một phần của cấu trúc tập tin PE và hoàn toàn zeroed-out (tức là các bytes trong Rich Header đều là 0x0) mà không ảnh hưởng đến các chức năng của chương trình khi thực thi```, nó chỉ xuất hiện khi chương trình có sử dụng công cụ ```Microsoft Visual Studio```. Cấu trúc này thường chứa các thông tin metadata về công cụ được sử dụng để biên dịch chương trình, thường là các thông tin mình cần quan tâm bao gồm: BuildID, phiên bản của công cụ Visual Studio.

1.4 NT Headers

- là cấu trúc được định nghĩa trong tập tin winnt.h với tên IMAGE_NT_HEADER. Tuỳ thuộc vào phiên bản hệ điều hành mà NT Header có 2 struct hỗ trợ đó là IMAGE_NT_HEADER (dành cho 32-bit) và IMAGE_NT_HEADER64 (dành cho 64-bit). Điểm khác biệt giữa 02 phiên bản trên đó là nó sử dụng struct IMAGE_OPTIONAL_HEADERS32 (dành cho 32-bit) và IMAGE_OPTIONAL_HEADERS64 (dành cho 64-bit).

```C
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

1.4.1 PE Signature

- là thành phần đầu tiên của NT Headers, có kiểu dữ liệu DWORD. PE Signature luôn có giá trị cố định là 0x50450000 (chuyển sang mã ASCII sẽ là PE\0\0).

1.4.1 File Header

- là một cấu trúc được định nghĩa trong tập tin winnt.h với tên IMAGE_FILE_HEADER có chức năng lưu trữ các thông tin cơ bản về tập tin và các con trỏ đến các bảng cấu trúc khác. Struct này có kích thước là 20 byte.

```C
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

- File Header gồm các thành phần như sau:
    
    - Machine: cho ta biết thông tin kiến trúc CPU mà tập tin thực thi sử dụng. Tại trường Machine có thể có nhiều giá trị, nhưng mà ta chỉ cần quan tâm đến 2 giá trị là ```0x8864``` dành cho kiến trúc AMD64 và ```0x14c``` dành cho kiến trúc i386.
    - NumberOfSections: Struct member này cho mình biết số lượng section (hoặc số lượng section, hay còn gọi là kích thước của Section table).
    - TimeDateStamp: Đây là dấu thời gian theo chuẩn Unix time, nó cho biết thời điểm tập tin được tạo ra.
    - PointerToSymbolTable và NumberOfSymbols: Hai trường này lần lượt chứa offset đến bảng COFF symbol (viết tắt của cụm từ ```Common Object File Format```, được sử dụng để lưu trữ các code đã được biên dịch) trong tập tin và số lượng mục trong bảng đó.
    - SizeOfOptionalHeader: kích thước của struct Optional Header.
    - Characteristics: Là một tập hợp các cờ (flags) biểu thị các thuộc tính của tập tin. Những thuộc tính này có thể bao gồm: quyền thực thi, tập tin được xác định là system file và không phải là user program, và nhiều thuộc tính khác.


# THAM KHẢO
    - https://0xrick.github.io/win-internals/pe2/
    - https://0xrick.github.io/win-internals/pe3/
    - https://sec.vnpt.vn/2022/05/kham-pha-cau-truc-cac-loai-file-bai-1-common-object-file-format-coff



1.4.2 Optional Header

- Optional Header là phần quan trọng nhất trong ntheader, bởi Pe loader sẽ tìm kiếm thông tin cụ thể từ header này để có thể chạy và thực thi chương trình.
- nó được gọi là optinal header vì 1 số file như object files không có có header này, nhưng optinal header là cần thiết cho 1 file ảnh (image file).
- nó không có size cố định, đó là lý do tại sao có struct "IMAGE_FILE_HEADER.SizeOfOptionalHeader" dùng để xác định kích thước của optinal header .
- 8 thành phần đầu trong struct của optinal header là chuẩn, đặc trưng với mọi trình thực thi của định dạng file COFF, phần còn lại là phần mở rộng được xác định với microsoft, những thành phần mở rộngrộng này là cần thiết cho Windows PE loader và linker.
- có 2 phiên bản của optinal header là file thực thi 32 bit và 64 bit, 2 phiên bản này khác nhau ở chỗ:
    - kích thước (hoặc số lượng thành phần của chúng) "IMAGE_OPTIONAL_HEADER32" có 31 thành phần còn "IMAGE_OPTIONAL_HEADER64" chỉ có 30. "IMAGE_OPTIONAL_HEADER32" có thêm một thành phần khác có kiểu "DWORD" tên là "BaseOfData" chứ RVA (Relative Virtual Address) (địa chỉ ảo tương đối) của điểm bắt dầu của data section.
    - kiểu dữ liệu của 1 số thành phần: 
                5 thành phần sau trong cấu trúc của optinal header là kiểu "DWORD" trong 32bit nhưng là "ULONGLONG" trogn 64bit:
      
                    ImageBase
                    SizeOfStackReserve
                    SizeOfStackCommit
                    SizeOfHeapReserve
                    SizeOfHeapCommit
- cấu trúc của 2 struct trên

```C
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

```C
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

<h4>Data Directories</h4>  

- thành phần cuối cùng trong struct "IMAGE_OPTIONAL_HEADE" là một mảng struct "IMAGE_DATA_DIRECTORY" được định nghĩa như sau 

```C
IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
```

- "IMAGE_NUMBEROF_DIRECTORY_ENTRIES" là hằng số có giá trị = 16, có nghĩa là mảng này có thể chứa được 16 mục "IMAGE_DATA_DIRECTORY":

```C
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
```

- một struct "IMAGE_DATA_DIRECTORY" gốm các thành phần sau: 

```C
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
đây là 1 struct khá đơn giản, đầu tiên là RVA chỉ đến điểm bắt đầu của Data Directory, sau đó là size của Data Directory

- Vậy, Data Directory là 1 phần dữ liệu nằm trong 1 trong các sections của PE files
- Data Directory chứa các thông tin quan trọng mà trong quá trình loader cần đến, ví dụ 1 directory quan trọng như Import Directory sẽ chứa 1 list các functions bên ngoài được import từ các thư viện khác

- lưu ý không phải mọi Data Directory đều có cùng 1 cấu trúc là "IMAGE_DATA_DIRECTORY.VirtualAddress" chỉ tới vị trí của Data Directory, nhưng kiểu dữ liệu của thư mục đó sẽ quyết định cách giải mã giữ liệu nằm trong vị trí đó 

- danh sách các Data Directory nằm trong 'winnt.h' (Mỗi giá trị bên dưới là chỉ số tương ứng trong mảng DataDirectory):

```C
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (Chỉ dùng trên X86)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Dữ liệu riêng của kiến trúc
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA của GP (Global Pointer)
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory trong headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

- nếu mở nội dung của "IMAGE_OPTIONAL_HEADER.DataDirectory" của 1 file PE thực tế, có thể thấy giá trị của cả 2 thành phần của nó đều = 0 thì có nghĩa Data Directory đó không được sử dụng trong file thực thi đó





1.5 Section và Section Header
      
