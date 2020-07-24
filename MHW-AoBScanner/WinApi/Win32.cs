using System;
using System.Runtime.InteropServices;

namespace MHW_AoBScanner.WinApi
{
    public class Win32
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            int dwDesiredAccess, 
            bool bInheritHandle, 
            int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            ref int lpNumberOfBytesRead);

        [DllImport("msvcrt.dll")]
        public static extern int memcmp(byte[] fArray, byte[] sArray, long count);
    }
}
