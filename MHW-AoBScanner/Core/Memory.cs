using MHW_AoBScanner.WinApi;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace MHW_AoBScanner.Core
{
    public class Memory
    {

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        public static string ProcessName => "MonsterHunterWorld";
        public static string GameVersion { get; private set; }
        public static IntPtr BaseAddress { get; private set; }
        public static IntPtr GameProcessHandle { get; private set; } = IntPtr.Zero;

        public static bool ScanForGame()
        {
            while (GameProcessHandle == IntPtr.Zero)
            {
                Process process = Process.GetProcessesByName(ProcessName).LastOrDefault();
                
                try
                {
                    GameProcessHandle = Win32.OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
                    if (GameProcessHandle == IntPtr.Zero)
                    {
                        Console.WriteLine("Missing permissions to open game process. Restart with administrator privileges.");
                        return false;
                    }
                    BaseAddress = process.MainModule.BaseAddress;
                    GameVersion = process.MainWindowTitle.Split('(')[1].Replace(")", "");
                    Console.WriteLine($"Detected build version: {GameVersion}");
                    return true;
                } catch { }
                
                Thread.Sleep(1000);
            }
            return false;
        }

        public static byte[] ReadBytes(long address, long size)
        {
            byte[] buffer = new byte[size];
            int bytesRead = 0;
            Win32.ReadProcessMemory(GameProcessHandle, (IntPtr)address, buffer, (int)size, ref bytesRead);
            return buffer;
        }

    }
}
