using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PDBFetch
{
    class PeRapid
    {
        public class PeParsingException : Exception
        {
            public PeParsingException()
            {
            }

            public PeParsingException(string msg) : base(msg)
            {
            }

            public PeParsingException(string msg, Exception inner) : base(msg, inner)
            {
            }
        }

        public class IMAGE_DOS_HEADER
        {

            public ushort e_magic { get; }              // Magic number
            public ushort e_cblp { get; }               // Bytes on last page of file
            public ushort e_cp { get; }                 // Pages in file
            public ushort e_crlc { get; }               // Relocations
            public ushort e_cparhdr { get; }            // Size of header in paragraphs
            public ushort e_minalloc { get; }           // Minimum extra paragraphs needed
            public ushort e_maxalloc { get; }           // Maximum extra paragraphs needed
            public ushort e_ss { get; }                 // Initial (relative) SS value
            public ushort e_sp { get; }                 // Initial SP value
            public ushort e_csum { get; }               // Checksum
            public ushort e_ip { get; }                 // Initial IP value
            public ushort e_cs { get; }                 // Initial (relative) CS value
            public ushort e_lfarlc { get; }             // File address of relocation table
            public ushort e_ovno { get; }               // Overlay number
            public ushort e_res_0 { get; }              // Reserved words
            public ushort e_res_1 { get; }              // Reserved words
            public ushort e_res_2 { get; }              // Reserved words
            public ushort e_res_3 { get; }              // Reserved words
            public ushort e_oemid { get; }              // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo { get; }            // OEM information; e_oemid specific
            public ushort e_res2_0 { get; }             // Reserved words
            public ushort e_res2_1 { get; }             // Reserved words
            public ushort e_res2_2 { get; }             // Reserved words
            public ushort e_res2_3 { get; }             // Reserved words
            public ushort e_res2_4 { get; }             // Reserved words
            public ushort e_res2_5 { get; }             // Reserved words
            public ushort e_res2_6 { get; }             // Reserved words
            public ushort e_res2_7 { get; }             // Reserved words
            public ushort e_res2_8 { get; }             // Reserved words
            public ushort e_res2_9 { get; }             // Reserved words
            public ushort e_lfanew { get; }             // File address of new exe header

            #region constructor
            public IMAGE_DOS_HEADER(BinaryReader reader)
            {
                e_magic = reader.ReadUInt16();
                e_cblp = reader.ReadUInt16();
                e_cp = reader.ReadUInt16();
                e_crlc = reader.ReadUInt16();
                e_cparhdr = reader.ReadUInt16();
                e_minalloc = reader.ReadUInt16();
                e_maxalloc = reader.ReadUInt16();
                e_ss = reader.ReadUInt16(); ;
                e_sp = reader.ReadUInt16();
                e_csum = reader.ReadUInt16();
                e_ip = reader.ReadUInt16();
                e_cs = reader.ReadUInt16();
                e_lfarlc = reader.ReadUInt16();
                e_ovno = reader.ReadUInt16();
                e_res_0 = reader.ReadUInt16();
                e_res_1 = reader.ReadUInt16();
                e_res_2 = reader.ReadUInt16();
                e_res_3 = reader.ReadUInt16();
                e_oemid = reader.ReadUInt16();
                e_res2_0 = reader.ReadUInt16();
                e_res2_1 = reader.ReadUInt16();
                e_res2_2 = reader.ReadUInt16();
                e_res2_3 = reader.ReadUInt16();
                e_res2_4 = reader.ReadUInt16();
                e_res2_5 = reader.ReadUInt16();
                e_res2_6 = reader.ReadUInt16();
                e_res2_7 = reader.ReadUInt16();
                e_res2_8 = reader.ReadUInt16();
                e_res2_9 = reader.ReadUInt16();
                e_lfanew = reader.ReadUInt16();
            }
            #endregion constructor
        }
        IMAGE_DOS_HEADER ImageDosHeader { get; }

        public class IMAGE_FILE_HEADER
        {
            public UInt16 Machine { get; }
            public UInt16 NumberOfSections { get; }
            public UInt32 TimeDateStamp { get; }
            public UInt32 PointerToSymbolTable { get; }
            public UInt32 NumberOfSymbols { get; }
            public UInt16 SizeOfOptionalHeader { get; }
            public UInt16 Characteristics { get; }
        }

        public class IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress { get; }
            public UInt32 Size { get; }
        }

        public class IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        public class IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        public class IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public dynamic OptionalHeader; // either IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64
        }

        #region constructor
        PeRapid(string filePath)
        {
            FileStream stream;
            try
            {
                stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            }
            catch
            {
                throw new PeParsingException("file cannot accessed");
            }

            BinaryReader reader;
            try
            {
                reader = new BinaryReader(stream);
            }
            catch
            {
                throw new PeParsingException("file cannot read");
            }

            try
            {
                ImageDosHeader = new IMAGE_DOS_HEADER(reader);
            }
            catch
            {
                throw new PeParsingException("bad dos header");
            }

            if (0x5a4d != ImageDosHeader.e_magic)
            {
                throw new PeParsingException("magic bytes not found");
            }
            

        }
        #endregion constructor
    }
}
