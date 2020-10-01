using System;
using System.Collections.Generic;
using System.Diagnostics;
using MHW_AoBScanner.Core;
using MHW_AoBScanner.WinApi;

namespace MHW_AoBScanner
{
    class Program
    {
        static readonly long start = 0x143000000;
        static readonly long end = 0x163ED2000;

        static Dictionary<byte, List<Signature>> signatures = new Dictionary<byte, List<Signature>>();
        static int signaturesCount = 0;
        static void Main(string[] args)
        {
            CreateSignatures();

            Memory.ScanForGame();
            FindSignatures();

            Console.ReadKey();
        }

        static void CreateSignatures()
        {
            List<Signature> sigs = new List<Signature>()
            {
                new Signature()
                {
                    Name = "CANTEEN_OFFSET",
                    Pattern = new Pattern("20 F2 ?? ?? 00 00 00 00 ?? ?? ?? 43 01"),
                    Offset = 0
                },
                new Signature()
                {
                    Name = "ZONE_OFFSET",
                    Pattern = new Pattern("A0 30 80 05 C7 34 64 11 00 00 00 00 00 00 00 00"),
                    Offset = -0x70
                },
                new Signature()
                {
                    Name = "MONSTER_TARGETED_OFFSET",
                    Pattern = new Pattern("01 00 00 00 1C 00 00 06 83 DB AF 62 2F"),
                    Offset = -0x34
                },
                new Signature()
                {
                    Name = "LEVEL_OFFSET",
                    Pattern = new Pattern("A0 81 ?? ?? 00 00 00 00 ?? ?? ?? 43 01 00 00 00 ?? ?? ?? 43 01"),
                    Offset = 0
                },
                new Signature()
                {
                    Name = "WEAPON_OFFSET",
                    Pattern = new Pattern("01 00 00 00 10 01 80 05 7D 68 64 22 ?? ?? ?? 43 01"),
                    Offset = -0x34
                },
                new Signature()
                {
                    Name = "WEAPON_MECHANICS_OFFSET",
                    Pattern = new Pattern("01 00 00 00 10 01 80 05 7D 68 64 22 ?? ?? ?? 43 01"),
                    Offset = -0x34
                },
                new Signature()
                {
                    Name = "EQUIPMENT_OFFSET",
                    Pattern = new Pattern("01 00 00 00 10 01 80 05 7D 68 64 22 ?? ?? ?? 43 01"),
                    Offset = -0x34
                },
                new Signature()
                {
                    Name = "ABNORMALITY_OFFSET",
                    Pattern = new Pattern("01 00 00 00 10 01 80 05 7D 68 64 22 ?? ?? ?? 43 01"),
                    Offset = -0x34
                },
                new Signature()
                {
                    Name = "MONSTER_OFFSET",
                    Pattern = new Pattern("45 01 00 00 00 0C 00 80 05 88 34 96 1D ?? ?? ?? 43 01"),
                    Offset = -0x33
                },
                new Signature()
                {
                    Name = "PARTY_OFFSET",
                    Pattern = new Pattern("45 01 00 00 00 52 01 80 05 BB D7 57 0A ?? ?? ??"),
                    Offset = -0x33
                },
                new Signature()
                {
                    Name = "SESSION_OFFSET",
                    Pattern = new Pattern("45 01 00 00 00 52 01 80 05 BB D7 57 0A ?? ?? ??"),
                    Offset = -0x33
                },
                new Signature()
                {
                    Name = "DAMAGE_OFFSET",
                    Pattern = new Pattern("45 01 00 00 00 52 01 80 05 BB D7 57 0A ?? ?? ??"),
                    Offset = -0x33
                },
                new Signature()
                {
                    Name = "MONSTER_SELECTED_OFFSET",
                    Pattern = new Pattern("0E 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 F0 E0 ?? ?? 00 00 00"),
                    Offset = -0x2B
                }
            };
            signaturesCount = sigs.Count;
            foreach (Signature sig in sigs)
            {
                if (!signatures.ContainsKey(sig.Pattern.Byte))
                {
                    signatures[sig.Pattern.Byte] = new List<Signature>()
                    {
                        sig
                    };
                } else
                {
                    signatures[sig.Pattern.Byte].Add(sig);
                }
            }
        }

        static void FindSignatures()
        {
            byte[] buffer = Memory.ReadBytes(start, end - start);
            byte[] sBuffer;

            Stopwatch timer = Stopwatch.StartNew();
            Console.WriteLine($"Starting AoB scan! Range={end - start} bytes");
            Console.WriteLine("\n--------------------------------------------------\n");

            for (int i = 0; i < buffer.Length; i++)
            {
                
                if (!signatures.ContainsKey(buffer[i])) continue;
                
                foreach (Signature signature in signatures[buffer[i]])
                {
                    if (signature.Found) continue;

                    sBuffer = new byte[signature.Length];
                    Buffer.BlockCopy(buffer, i, sBuffer, 0, signature.Length);
                    
                    if (signature.Pattern.Equals(sBuffer))
                    {
                        signature.Found = true;
                        signaturesCount--;
                        Console.WriteLine($"Address {signature.Name} 0x{(start - (long)Memory.BaseAddress) + i + signature.Offset:X8}");
                    }
                }

                if (signaturesCount == 0) break;
            }
            timer.Stop();
            Console.WriteLine("\n--------------------------------------------------\n");
            Console.WriteLine($"Finished in {timer.ElapsedMilliseconds}ms");
        }
    }
}
