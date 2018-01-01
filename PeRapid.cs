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

            private string _e_magic
            {
                get { return new string(e_magic.Select(b => (char)b).ToArray()); }
            }

            public bool IsValid => _e_magic == "MZ";
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
            //public ushort e_res_0 { get; }              // Reserved words
            //public ushort e_res_1 { get; }              // Reserved words
            //public ushort e_res_2 { get; }              // Reserved words
            //public ushort e_res_3 { get; }              // Reserved words
            public ushort e_oemid { get; }              // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo { get; }            // OEM information; e_oemid specific
            public ushort[] e_res2 { get; }
            //public ushort e_res2_0 { get; }             // Reserved words
            //public ushort e_res2_1 { get; }             // Reserved words
            //public ushort e_res2_2 { get; }             // Reserved words
            //public ushort e_res2_3 { get; }             // Reserved words
            //public ushort e_res2_4 { get; }             // Reserved words
            //public ushort e_res2_5 { get; }             // Reserved words
            //public ushort e_res2_6 { get; }             // Reserved words
            //public ushort e_res2_7 { get; }             // Reserved words
            //public ushort e_res2_8 { get; }             // Reserved words
            //public ushort e_res2_9 { get; }             // Reserved words
            public uint e_lfanew { get; }             // File address of new exe header

            #region constructor
            public IMAGE_DOS_HEADER(BinaryReader reader)
            {
                var nativeStruct = ExtractNativeStructure<NATIVE_IMAGE_DOS_HEADER>(reader);
                if (!nativeStruct.IsValid)
                {
                    throw new PeParsingException("bad MZ magic bytes");
                }

                e_magic = BitConverter.ToUInt16(nativeStruct.e_magic, 0);
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
                //e_magic = reader.ReadUInt16();
                //if (0x5a4d != e_magic)
                //{
                //    throw new PeParsingException("bad MZ magic bytes");
                //}

                //e_cblp = reader.ReadUInt16();
                //e_cp = reader.ReadUInt16();
                //e_crlc = reader.ReadUInt16();
                //e_cparhdr = reader.ReadUInt16();
                //e_minalloc = reader.ReadUInt16();
                //e_maxalloc = reader.ReadUInt16();
                //e_ss = reader.ReadUInt16(); ;
                //e_sp = reader.ReadUInt16();
                //e_csum = reader.ReadUInt16();
                //e_ip = reader.ReadUInt16();
                //e_cs = reader.ReadUInt16();
                //e_lfarlc = reader.ReadUInt16();
                //e_ovno = reader.ReadUInt16();
                //e_res_0 = reader.ReadUInt16();
                //e_res_1 = reader.ReadUInt16();
                //e_res_2 = reader.ReadUInt16();
                //e_res_3 = reader.ReadUInt16();
                //e_oemid = reader.ReadUInt16();
                //e_res2_0 = reader.ReadUInt16();
                //e_res2_1 = reader.ReadUInt16();
                //e_res2_2 = reader.ReadUInt16();
                //e_res2_3 = reader.ReadUInt16();
                //e_res2_4 = reader.ReadUInt16();
                //e_res2_5 = reader.ReadUInt16();
                //e_res2_6 = reader.ReadUInt16();
                //e_res2_7 = reader.ReadUInt16();
                //e_res2_8 = reader.ReadUInt16();
                //e_res2_9 = reader.ReadUInt16();
                //e_lfanew = reader.ReadUInt16();
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

            public IMAGE_FILE_HEADER(BinaryReader reader)
            {
                Machine = reader.ReadUInt16();
            }
        }

        public class IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress { get; }
            public UInt32 Size { get; }
        }

        public class IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic { get; }
            public Byte MajorLinkerVersion { get; }
            public Byte MinorLinkerVersion { get; }
            public UInt32 SizeOfCode { get; }
            public UInt32 SizeOfInitializedData { get; }
            public UInt32 SizeOfUninitializedData { get; }
            public UInt32 AddressOfEntryPoint { get; }
            public UInt32 BaseOfCode { get; }
            public UInt32 BaseOfData { get; }
            public UInt32 ImageBase { get; }
            public UInt32 SectionAlignment { get; }
            public UInt32 FileAlignment { get; }
            public UInt16 MajorOperatingSystemVersion { get; }
            public UInt16 MinorOperatingSystemVersion { get; }
            public UInt16 MajorImageVersion { get; }
            public UInt16 MinorImageVersion { get; }
            public UInt16 MajorSubsystemVersion { get; }
            public UInt16 MinorSubsystemVersion { get; }
            public UInt32 Win32VersionValue { get; }
            public UInt32 SizeOfImage { get; }
            public UInt32 SizeOfHeaders { get; }
            public UInt32 CheckSum { get; }
            public UInt16 Subsystem { get; }
            public UInt16 DllCharacteristics { get; }
            public UInt32 SizeOfStackReserve { get; }
            public UInt32 SizeOfStackCommit { get; }
            public UInt32 SizeOfHeapReserve { get; }
            public UInt32 SizeOfHeapCommit { get; }
            public UInt32 LoaderFlags { get; }
            public UInt32 NumberOfRvaAndSizes { get; }

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
        }

        public class IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic { get; }
            public Byte MajorLinkerVersion { get; }
            public Byte MinorLinkerVersion { get; }
            public UInt32 SizeOfCode { get; }
            public UInt32 SizeOfInitializedData { get; }
            public UInt32 SizeOfUninitializedData { get; }
            public UInt32 AddressOfEntryPoint { get; }
            public UInt32 BaseOfCode { get; }
            public UInt64 ImageBase { get; }
            public UInt32 SectionAlignment { get; }
            public UInt32 FileAlignment { get; }
            public UInt16 MajorOperatingSystemVersion { get; }
            public UInt16 MinorOperatingSystemVersion { get; }
            public UInt16 MajorImageVersion { get; }
            public UInt16 MinorImageVersion { get; }
            public UInt16 MajorSubsystemVersion { get; }
            public UInt16 MinorSubsystemVersion { get; }
            public UInt32 Win32VersionValue { get; }
            public UInt32 SizeOfImage { get; }
            public UInt32 SizeOfHeaders { get; }
            public UInt32 CheckSum { get; }
            public UInt16 Subsystem { get; }
            public UInt16 DllCharacteristics { get; }
            public UInt64 SizeOfStackReserve { get; }
            public UInt64 SizeOfStackCommit { get; }
            public UInt64 SizeOfHeapReserve { get; }
            public UInt64 SizeOfHeapCommit { get; }
            public UInt32 LoaderFlags { get; }
            public UInt32 NumberOfRvaAndSizes { get; }

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
        }

        public class IMAGE_NT_HEADERS
        {
            public uint Signature { get; }
            public IMAGE_FILE_HEADER FileHeader { get; }
            /// <summary>
            /// either IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64
            /// </summary>
            public dynamic OptionalHeader { get; }

            public IMAGE_NT_HEADERS(BinaryReader reader)
            {
                Signature = reader.ReadUInt32();
                if (0x4550 != Signature)
                {
                    throw new PeParsingException("bad PE signature");
                }


            }
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
            catch(PeParsingException)
            {
                //throw new PeParsingException("bad dos header");
                throw;
            }
            catch
            {
                throw new PeParsingException("bad dos header");
            }
            
            

        }
        #endregion constructor
    }
}
