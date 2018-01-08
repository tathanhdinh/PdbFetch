using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PDBFetch
{
    class PeRapid
    {
        private static T ExtractNativeStructure<T>(BinaryReader reader)
        {
            var rawNativeStructure = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            var handle = GCHandle.Alloc(rawNativeStructure, GCHandleType.Pinned);
            var extractedStruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return extractedStruct;
        }

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

        // from PInvoke.net
        [StructLayout(LayoutKind.Sequential)]
        private struct NATIVE_IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] e_magic;       // Magic number
            public UInt16 e_cblp;        // Bytes on last page of file
            public UInt16 e_cp;          // Pages in file
            public UInt16 e_crlc;        // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;          // Initial (relative) SS value
            public UInt16 e_sp;          // Initial SP value
            public UInt16 e_csum;        // Checksum
            public UInt16 e_ip;          // Initial IP value
            public UInt16 e_cs;          // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;        // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;      // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;      // Reserved words
            public UInt32 e_lfanew;      // File address of new exe header

            //private string _e_magic
            //{
            //    get { return new string(e_magic.Select(b => (char)b).ToArray()); }
            //}

            //public bool IsValid => _e_magic == "MZ";
        }

        // Credits: John Stewien
        // From: http://code.cheesydesign.com/?p=572
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
            public ushort[] e_res1 { get; }
            public ushort e_oemid { get; }              // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo { get; }            // OEM information; e_oemid specific
            public ushort[] e_res2 { get; }
            public uint e_lfanew { get; }               // File address of new exe header

            public IMAGE_DOS_HEADER(BinaryReader reader)
            {
                var nativeStruct = ExtractNativeStructure<NATIVE_IMAGE_DOS_HEADER>(reader);
                //if (!nativeStruct.IsValid)
                //{
                //    throw new PeParsingException("bad MZ magic bytes");
                //}

                e_magic = BitConverter.ToUInt16(nativeStruct.e_magic, 0);
                if (e_magic != 0x5a4d)
                {
                    throw new PeParsingException("bad MZ magic bytes");
                }
                e_cblp = nativeStruct.e_cblp;
                e_cp = nativeStruct.e_cp;
                e_cparhdr = nativeStruct.e_cparhdr;
                e_minalloc = nativeStruct.e_minalloc;
                e_maxalloc = nativeStruct.e_maxalloc;
                e_ss = nativeStruct.e_ss;
                e_sp = nativeStruct.e_sp;
                e_csum = nativeStruct.e_csum;
                e_ip = nativeStruct.e_ip;
                e_cs = nativeStruct.e_cs;
                e_lfarlc = nativeStruct.e_lfarlc;
                e_ovno = nativeStruct.e_ovno;
                e_res1 = nativeStruct.e_res1;
                e_oemid = nativeStruct.e_oemid;
                e_res2 = nativeStruct.e_res2;
                e_lfanew = nativeStruct.e_lfanew;
            }
        }
        IMAGE_DOS_HEADER ImageDosHeader { get; }

        // from PInvoke.net
        [StructLayout(LayoutKind.Sequential)]
        private struct NATIVE_IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum ImageFileMachine : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
            IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
            IMAGE_FILE_MACHINE_EBC = 0xebc,
            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
            IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
            IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664
        }

        [Flags]
        public enum ImageFileCharacteristics : ushort
        {
            IMAGE_FILE_RELOCS_STRIPPED = 0x1,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x2,
            IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4,
            IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8,
            IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x10,
            IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20,
            IMAGE_FILE_BYTES_REVERSED_LO = 0x80,
            IMAGE_FILE_32BIT_MACHINE = 0x100,
            IMAGE_FILE_DEBUG_STRIPPED = 0x200,
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400,
            IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800,
            IMAGE_FILE_SYSTEM = 0x1000,
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
            IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
        }

        public class IMAGE_FILE_HEADER
        {
            public ImageFileMachine Machine { get; }
            public ushort NumberOfSections { get; }
            public uint TimeDateStamp { get; }
            public uint PointerToSymbolTable { get; }
            public uint NumberOfSymbols { get; }
            public ushort SizeOfOptionalHeader { get; }
            public ImageFileCharacteristics Characteristics { get; }

            public IMAGE_FILE_HEADER(BinaryReader reader)
            {
                var nativeStruct = ExtractNativeStructure<NATIVE_IMAGE_FILE_HEADER>(reader);

                Machine = (ImageFileMachine)nativeStruct.Machine;
                NumberOfSections = nativeStruct.NumberOfSections;
                TimeDateStamp = nativeStruct.TimeDateStamp;
                PointerToSymbolTable = nativeStruct.PointerToSymbolTable;
                NumberOfSymbols = nativeStruct.NumberOfSymbols;
                SizeOfOptionalHeader = nativeStruct.SizeOfOptionalHeader;
                Characteristics = (ImageFileCharacteristics)nativeStruct.Characteristics;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NATIVE_IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct NATIVE_IMAGE_OPTIONAL_HEADER32
        {
            #region Separated properties
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
            #endregion

            #region Data directories
            public NATIVE_IMAGE_DATA_DIRECTORY ExportTable;
            public NATIVE_IMAGE_DATA_DIRECTORY ImportTable;
            public NATIVE_IMAGE_DATA_DIRECTORY ResourceTable;
            public NATIVE_IMAGE_DATA_DIRECTORY ExceptionTable;
            public NATIVE_IMAGE_DATA_DIRECTORY CertificateTable;
            public NATIVE_IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public NATIVE_IMAGE_DATA_DIRECTORY Debug;
            public NATIVE_IMAGE_DATA_DIRECTORY Architecture;
            public NATIVE_IMAGE_DATA_DIRECTORY GlobalPtr;
            public NATIVE_IMAGE_DATA_DIRECTORY TLSTable;
            public NATIVE_IMAGE_DATA_DIRECTORY LoadConfigTable;
            public NATIVE_IMAGE_DATA_DIRECTORY BoundImport;
            public NATIVE_IMAGE_DATA_DIRECTORY IAT;
            public NATIVE_IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public NATIVE_IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public NATIVE_IMAGE_DATA_DIRECTORY Reserved;
            #endregion
        }

        public class IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress { get; }
            public uint Size { get; }

            //public IMAGE_DATA_DIRECTORY(uint virtualAddress, uint size)
            internal IMAGE_DATA_DIRECTORY(NATIVE_IMAGE_DATA_DIRECTORY nativeDir)
            {
                //VirtualAddress = virtualAddress;
                //Size = size;
                VirtualAddress = nativeDir.VirtualAddress;
                Size = nativeDir.Size;
            }
        }

        public enum ImageOptionalMagic : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            MAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
            IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
        }

        public enum ImageOptionalSubsytem : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_OS2_CUI = 5,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
        }

        [Flags]
        public enum ImageOptionalDllCharacteristics : ushort
        {
            Reserved0 = 0x1,
            Reserved1 = 0x2,
            Reserved2 = 0x4,
            Reserved3 = 0x8,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20,
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40,
            IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80,
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800,
            IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }


        public class IMAGE_OPTIONAL_HEADER32
        {
            #region Separated properties
            public ImageOptionalMagic Magic { get; }
            public byte MajorLinkerVersion { get; }
            public byte MinorLinkerVersion { get; }
            public uint SizeOfCode { get; }
            public uint SizeOfInitializedData { get; }
            public uint SizeOfUninitializedData { get; }
            public uint AddressOfEntryPoint { get; }
            public uint BaseOfCode { get; }
            public uint BaseOfData { get; }
            public uint ImageBase { get; }
            public uint SectionAlignment { get; }
            public uint FileAlignment { get; }
            public ushort MajorOperatingSystemVersion { get; }
            public ushort MinorOperatingSystemVersion { get; }
            public ushort MajorImageVersion { get; }
            public ushort MinorImageVersion { get; }
            public ushort MajorSubsystemVersion { get; }
            public ushort MinorSubsystemVersion { get; }
            public uint Win32VersionValue { get; }
            public uint SizeOfImage { get; }
            public uint SizeOfHeaders { get; }
            public uint CheckSum { get; }
            public ImageOptionalSubsytem Subsystem { get; }
            public ImageOptionalDllCharacteristics DllCharacteristics { get; }
            public uint SizeOfStackReserve { get; }
            public uint SizeOfStackCommit { get; }
            public uint SizeOfHeapReserve { get; }
            public uint SizeOfHeapCommit { get; }
            public uint LoaderFlags { get; }
            public uint NumberOfRvaAndSizes { get; }
            #endregion

            #region Image data directories
            public IMAGE_DATA_DIRECTORY ExportTable { get; }
            public IMAGE_DATA_DIRECTORY ImportTable { get; }
            public IMAGE_DATA_DIRECTORY ResourceTable { get; }
            public IMAGE_DATA_DIRECTORY ExceptionTable { get; }
            public IMAGE_DATA_DIRECTORY CertificateTable { get; }
            public IMAGE_DATA_DIRECTORY BaseRelocationTable { get; }
            public IMAGE_DATA_DIRECTORY Debug { get; }
            public IMAGE_DATA_DIRECTORY Architecture { get; }
            public IMAGE_DATA_DIRECTORY GlobalPtr { get; }
            public IMAGE_DATA_DIRECTORY TLSTable { get; }
            public IMAGE_DATA_DIRECTORY LoadConfigTable { get; }
            public IMAGE_DATA_DIRECTORY BoundImport { get; }
            public IMAGE_DATA_DIRECTORY IAT { get; }
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor { get; }
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader { get; }
            public IMAGE_DATA_DIRECTORY Reserved { get; }
            #endregion

            public IMAGE_OPTIONAL_HEADER32(BinaryReader reader)
            {
                var nativeStructure = ExtractNativeStructure<NATIVE_IMAGE_OPTIONAL_HEADER32>(reader);

                #region Assign separated properties
                Magic = (ImageOptionalMagic)nativeStructure.Magic;
                MajorLinkerVersion = nativeStructure.MajorLinkerVersion;
                MinorLinkerVersion = nativeStructure.MinorLinkerVersion;
                SizeOfCode = nativeStructure.SizeOfCode;
                SizeOfInitializedData = nativeStructure.SizeOfInitializedData;
                SizeOfUninitializedData = nativeStructure.SizeOfUninitializedData;
                AddressOfEntryPoint = nativeStructure.AddressOfEntryPoint;
                BaseOfCode = nativeStructure.BaseOfCode;
                BaseOfData = nativeStructure.BaseOfData;
                ImageBase = nativeStructure.ImageBase;
                SectionAlignment = nativeStructure.SectionAlignment;
                FileAlignment = nativeStructure.FileAlignment;
                MajorOperatingSystemVersion = nativeStructure.MajorOperatingSystemVersion;
                MinorOperatingSystemVersion = nativeStructure.MinorOperatingSystemVersion;
                MajorSubsystemVersion = nativeStructure.MajorSubsystemVersion;
                MinorSubsystemVersion = nativeStructure.MinorSubsystemVersion;
                Win32VersionValue = nativeStructure.Win32VersionValue;
                SizeOfImage = nativeStructure.SizeOfImage;
                SizeOfHeaders = nativeStructure.SizeOfHeaders;
                CheckSum = nativeStructure.CheckSum;
                Subsystem = (ImageOptionalSubsytem)nativeStructure.Subsystem;
                DllCharacteristics = (ImageOptionalDllCharacteristics)nativeStructure.DllCharacteristics;
                SizeOfStackReserve = nativeStructure.SizeOfStackReserve;
                SizeOfStackCommit = nativeStructure.SizeOfStackCommit;
                SizeOfHeapReserve = nativeStructure.SizeOfHeapReserve;
                SizeOfHeapCommit = nativeStructure.SizeOfHeapCommit;
                LoaderFlags = nativeStructure.LoaderFlags;
                NumberOfRvaAndSizes = nativeStructure.NumberOfRvaAndSizes;
                #endregion

                #region Assign data directories
                ExportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExportTable);
                ImportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ImportTable);
                ResourceTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ResourceTable);
                ExceptionTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExceptionTable);
                CertificateTable = new IMAGE_DATA_DIRECTORY(nativeStructure.CertificateTable);
                BaseRelocationTable = new IMAGE_DATA_DIRECTORY(nativeStructure.BaseRelocationTable);
                Debug = new IMAGE_DATA_DIRECTORY(nativeStructure.Debug);
                Architecture = new IMAGE_DATA_DIRECTORY(nativeStructure.Architecture);
                GlobalPtr = new IMAGE_DATA_DIRECTORY(nativeStructure.GlobalPtr);
                TLSTable = new IMAGE_DATA_DIRECTORY(nativeStructure.TLSTable);
                LoadConfigTable = new IMAGE_DATA_DIRECTORY(nativeStructure.LoadConfigTable);
                BoundImport = new IMAGE_DATA_DIRECTORY(nativeStructure.BoundImport);
                IAT = new IMAGE_DATA_DIRECTORY(nativeStructure.IAT);
                DelayImportDescriptor = new IMAGE_DATA_DIRECTORY(nativeStructure.DelayImportDescriptor);
                CLRRuntimeHeader = new IMAGE_DATA_DIRECTORY(nativeStructure.CLRRuntimeHeader);
                Reserved = new IMAGE_DATA_DIRECTORY(nativeStructure.Reserved);
                //ExportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExportTable.VirtualAddress, nativeStructure.ExportTable.Size);
                //ImportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ImportTable.VirtualAddress, nativeStructure.ImportTable.Size);
                //ResourceTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ResourceTable.VirtualAddress, nativeStructure.ResourceTable.Size);
                //ExceptionTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExceptionTable.VirtualAddress, nativeStructure.ResourceTable.Size);
                //CertificateTable = new IMAGE_DATA_DIRECTORY(nativeStructure.CertificateTable.VirtualAddress, nativeStructure.CertificateTable.Size);
                //BaseRelocationTable = new IMAGE_DATA_DIRECTORY(nativeStructure.BaseRelocationTable.VirtualAddress, nativeStructure.BaseRelocationTable.Size);
                //Debug = new IMAGE_DATA_DIRECTORY(nativeStructure.Debug.VirtualAddress, nativeStructure.Debug.Size);
                //Architecture = new IMAGE_DATA_DIRECTORY(nativeStructure.Architecture.VirtualAddress, nativeStructure.Architecture.Size);
                //GlobalPtr = new IMAGE_DATA_DIRECTORY(nativeStructure.GlobalPtr.VirtualAddress, nativeStructure.GlobalPtr.Size);
                //TLSTable = new IMAGE_DATA_DIRECTORY(nativeStructure.TLSTable.VirtualAddress, nativeStructure.TLSTable.Size);
                //LoadConfigTable = new IMAGE_DATA_DIRECTORY(nativeStructure.LoadConfigTable.VirtualAddress, nativeStructure.LoadConfigTable.Size);
                //BoundImport = new IMAGE_DATA_DIRECTORY(nativeStructure.BoundImport.VirtualAddress, nativeStructure.BoundImport.Size);
                //IAT = new IMAGE_DATA_DIRECTORY(nativeStructure.IAT.VirtualAddress, nativeStructure.IAT.Size);
                //DelayImportDescriptor = new IMAGE_DATA_DIRECTORY(nativeStructure.DelayImportDescriptor.VirtualAddress, nativeStructure.DelayImportDescriptor.Size);
                //CLRRuntimeHeader = new IMAGE_DATA_DIRECTORY(nativeStructure.CLRRuntimeHeader.VirtualAddress, nativeStructure.CLRRuntimeHeader.Size);
                //Reserved = new IMAGE_DATA_DIRECTORY(nativeStructure.Reserved.VirtualAddress, nativeStructure.Reserved.Size);
                #endregion
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct NATIVE_IMAGE_OPTIONAL_HEADER64
        {
            #region Separated properties
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
            #endregion

            #region Image data directories
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
            #endregion
        }

        public class IMAGE_OPTIONAL_HEADER64
        {
            #region Separated properties
            public ImageOptionalMagic Magic { get; }
            public byte MajorLinkerVersion { get; }
            public byte MinorLinkerVersion { get; }
            public uint SizeOfCode { get; }
            public uint SizeOfInitializedData { get; }
            public uint SizeOfUninitializedData { get; }
            public uint AddressOfEntryPoint { get; }
            public uint BaseOfCode { get; }
            public ulong ImageBase { get; }
            public uint SectionAlignment { get; }
            public uint FileAlignment { get; }
            public ushort MajorOperatingSystemVersion { get; }
            public ushort MinorOperatingSystemVersion { get; }
            public ushort MajorImageVersion { get; }
            public ushort MinorImageVersion { get; }
            public ushort MajorSubsystemVersion { get; }
            public ushort MinorSubsystemVersion { get; }
            public uint Win32VersionValue { get; }
            public uint SizeOfImage { get; }
            public uint SizeOfHeaders { get; }
            public uint CheckSum { get; }
            public ImageOptionalSubsytem Subsystem { get; }
            public ImageOptionalDllCharacteristics DllCharacteristics { get; }
            public ulong SizeOfStackReserve { get; }
            public ulong SizeOfStackCommit { get; }
            public ulong SizeOfHeapReserve { get; }
            public ulong SizeOfHeapCommit { get; }
            public uint LoaderFlags { get; }
            public uint NumberOfRvaAndSizes { get; }
            #endregion

            #region Data directories
            public IMAGE_DATA_DIRECTORY ExportTable { get; }
            public IMAGE_DATA_DIRECTORY ImportTable { get; }
            public IMAGE_DATA_DIRECTORY ResourceTable { get; }
            public IMAGE_DATA_DIRECTORY ExceptionTable { get; }
            public IMAGE_DATA_DIRECTORY CertificateTable { get; }
            public IMAGE_DATA_DIRECTORY BaseRelocationTable { get; }
            public IMAGE_DATA_DIRECTORY Debug { get; }
            public IMAGE_DATA_DIRECTORY Architecture { get; }
            public IMAGE_DATA_DIRECTORY GlobalPtr { get; }
            public IMAGE_DATA_DIRECTORY TLSTable { get; }
            public IMAGE_DATA_DIRECTORY LoadConfigTable { get; }
            public IMAGE_DATA_DIRECTORY BoundImport { get; }
            public IMAGE_DATA_DIRECTORY IAT { get; }
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor { get; }
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader { get; }
            public IMAGE_DATA_DIRECTORY Reserved { get; }
            #endregion

            public IMAGE_OPTIONAL_HEADER64(BinaryReader reader)
            {
                var nativeStructure = ExtractNativeStructure<NATIVE_IMAGE_OPTIONAL_HEADER32>(reader);

                #region Assign separated properties
                Magic = (ImageOptionalMagic)nativeStructure.Magic;
                MajorLinkerVersion = nativeStructure.MajorLinkerVersion;
                MinorLinkerVersion = nativeStructure.MinorLinkerVersion;
                SizeOfCode = nativeStructure.SizeOfCode;
                SizeOfInitializedData = nativeStructure.SizeOfInitializedData;
                SizeOfUninitializedData = nativeStructure.SizeOfUninitializedData;
                AddressOfEntryPoint = nativeStructure.AddressOfEntryPoint;
                BaseOfCode = nativeStructure.BaseOfCode;
                ImageBase = nativeStructure.ImageBase;
                SectionAlignment = nativeStructure.SectionAlignment;
                FileAlignment = nativeStructure.FileAlignment;
                MajorOperatingSystemVersion = nativeStructure.MajorOperatingSystemVersion;
                MinorOperatingSystemVersion = nativeStructure.MinorOperatingSystemVersion;
                MajorImageVersion = nativeStructure.MajorImageVersion;
                MinorImageVersion = nativeStructure.MinorImageVersion;
                MajorSubsystemVersion = nativeStructure.MajorSubsystemVersion;
                MinorSubsystemVersion = nativeStructure.MinorSubsystemVersion;
                Win32VersionValue = nativeStructure.Win32VersionValue;
                SizeOfImage = nativeStructure.SizeOfImage;
                SizeOfHeaders = nativeStructure.SizeOfHeaders;
                CheckSum = nativeStructure.CheckSum;
                Subsystem = (ImageOptionalSubsytem)nativeStructure.Subsystem;
                DllCharacteristics = (ImageOptionalDllCharacteristics)nativeStructure.DllCharacteristics;
                SizeOfStackReserve = nativeStructure.SizeOfStackReserve;
                SizeOfStackCommit = nativeStructure.SizeOfStackCommit;
                SizeOfHeapReserve = nativeStructure.SizeOfHeapReserve;
                SizeOfHeapCommit = nativeStructure.SizeOfHeapCommit;
                LoaderFlags = nativeStructure.LoaderFlags;
                NumberOfRvaAndSizes = nativeStructure.NumberOfRvaAndSizes;
                #endregion

                #region Assign data directories
                ExportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExportTable);
                ImportTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ImportTable);
                ResourceTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ResourceTable);
                ExceptionTable = new IMAGE_DATA_DIRECTORY(nativeStructure.ExceptionTable);
                CertificateTable = new IMAGE_DATA_DIRECTORY(nativeStructure.CertificateTable);
                BaseRelocationTable = new IMAGE_DATA_DIRECTORY(nativeStructure.BaseRelocationTable);
                Debug = new IMAGE_DATA_DIRECTORY(nativeStructure.Debug);
                Architecture = new IMAGE_DATA_DIRECTORY(nativeStructure.Architecture);
                GlobalPtr = new IMAGE_DATA_DIRECTORY(nativeStructure.GlobalPtr);
                TLSTable = new IMAGE_DATA_DIRECTORY(nativeStructure.TLSTable);
                LoadConfigTable = new IMAGE_DATA_DIRECTORY(nativeStructure.LoadConfigTable);
                BoundImport = new IMAGE_DATA_DIRECTORY(nativeStructure.BoundImport);
                IAT = new IMAGE_DATA_DIRECTORY(nativeStructure.IAT);
                DelayImportDescriptor = new IMAGE_DATA_DIRECTORY(nativeStructure.DelayImportDescriptor);
                CLRRuntimeHeader = new IMAGE_DATA_DIRECTORY(nativeStructure.CLRRuntimeHeader);
                Reserved = new IMAGE_DATA_DIRECTORY(nativeStructure.Reserved);
                #endregion
            }
        }

        public class IMAGE_NT_HEADERS
        {
            public uint Signature { get; }
            public IMAGE_FILE_HEADER FileHeader { get; }
            public dynamic OptionalHeader { get; } // either IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64

            public IMAGE_NT_HEADERS(BinaryReader reader)
            {
                Signature = reader.ReadUInt32();
                if (0x4550 != Signature)
                {
                    throw new PeParsingException("bad PE signature");
                }

                FileHeader = new IMAGE_FILE_HEADER(reader);

                switch (FileHeader.Machine)
                {
                    case ImageFileMachine.IMAGE_FILE_MACHINE_AMD64:
                        OptionalHeader = new IMAGE_OPTIONAL_HEADER64(reader);
                        break;

                    case ImageFileMachine.IMAGE_FILE_MACHINE_I386:
                        OptionalHeader = new IMAGE_OPTIONAL_HEADER32(reader);
                        break;

                    default:
                        throw new PeParsingException("unsupported machine type");
                }
            }
        }

        [Flags]
        public enum ImageSectionCharacteristics : uint
        {
            Reserved0 = 0x0,
            Reserved1 = 0x1,
            Reserved2 = 0x2,
            Reserved3 = 0x4,
            IMAGE_SCN_TYPE_NO_PAD = 0x8,
            Reserved4 = 0x10,
            IMAGE_SCN_CNT_CODE = 0x20,
            IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80,
            IMAGE_SCN_LNK_OTHER = 0x100,
            IMAGE_SCN_LNK_INFO = 0x200,
            Reserved5 = 0x400,
            IMAGE_SCN_LNK_REMOVE = 0x800,
            IMAGE_SCN_LNK_COMDAT = 0x1000,
            IMAGE_SCN_GPREL = 0x00008000,
            IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
            IMAGE_SCN_MEM_16BIT = 0x00020000,
            IMAGE_SCN_MEM_LOCKED = 0x00020000,
            IMAGE_SCN_MEM_PRELOAD = 0x00020000,
            IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
            IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
            IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
            IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
            IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
            IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
            IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
            IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
            IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
            IMAGE_SCN_ALIGN_512BYTES = 0x00a00000,
            IMAGE_SCN_ALIGN_1024BYTES = 0x00b00000,
            IMAGE_SCN_ALIGN_2048BYTES = 0x00c00000,
            IMAGE_SCN_ALIGN_4096BYTES = 0x00d00000,
            IMAGE_SCN_ALIGN_8192BYTES = 0x00e00000,
            IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
            IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
            IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
            IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
            IMAGE_SCN_MEM_SHARED = 0x10000000,
            IMAGE_SCN_MEM_EXECUTE = 0x20000000,
            IMAGE_SCN_MEM_READ = 0x40000000,
            IMAGE_SCN_MEM_WRITE = 0x80000000
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct NATIVE_IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLineNumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLineNumbers;

            [FieldOffset(36)]
            public UInt32 Characteristics;

            //public string Section
            //{
            //    get { return new string(Name); }
            //}
        }

        public class IMAGE_SECTION_HEADER
        {
            public char[] Name { get; }
            public uint VirtualSize { get; }
            public uint VirtualAddress { get; }
            public uint SizeOfRawData { get; }
            public uint PointerToRawData { get; }
            public uint PointerToRelocations { get; }
            public uint PointerToLineNumbers { get; }
            public ushort NumberOfRelocations { get; }
            public ushort NumberOfLineNumbers { get; }
            public ImageSectionCharacteristics Characteristics { get; }

            public IMAGE_SECTION_HEADER(BinaryReader reader)
            {
                var nativeStructure = ExtractNativeStructure<NATIVE_IMAGE_SECTION_HEADER>(reader);

                Name = nativeStructure.Name;
                VirtualSize = nativeStructure.VirtualSize;
                VirtualAddress = nativeStructure.VirtualAddress;
                SizeOfRawData = nativeStructure.SizeOfRawData;
                PointerToRawData = nativeStructure.PointerToRawData;
                PointerToRelocations = nativeStructure.PointerToRelocations;
                PointerToLineNumbers = nativeStructure.PointerToLineNumbers;
                NumberOfRelocations = nativeStructure.NumberOfRelocations;
                Characteristics = (ImageSectionCharacteristics)nativeStructure.Characteristics;
            }
        }
        public IMAGE_SECTION_HEADER ImageSectionHeader { get; }

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

            // read IMAGE_DOS_HEADER
            try
            {
                ImageDosHeader = new IMAGE_DOS_HEADER(reader);
            }
            catch(PeParsingException)
            {
                // rethrow
                throw;
            }
            catch // other exceptions
            {
                throw new PeParsingException("bad dos header");
            }

            // read IMAGE_NT_HEADERS
            try
            {
                stream.Seek(ImageDosHeader.e_lfanew, SeekOrigin.Begin);
            }
            catch
            {
                throw new PeParsingException("cannot seek to IMAGE_NT_HEADERS offset");
            }
            ImageSectionHeader = new IMAGE_SECTION_HEADER(reader);
        }
        #endregion constructor
    }
}
