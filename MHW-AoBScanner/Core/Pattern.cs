using MHW_AoBScanner.WinApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MHW_AoBScanner.Core
{
    public class Pattern
    {

        public string String { get; private set; }
        public byte[] Bytes { get; private set; }
        public List<int> Wildcards { get; private set; }
        public int Length => Bytes.Length;
        public byte Byte => Bytes.FirstOrDefault();

        public Pattern(string pattern)
        {
            String = pattern;
            ConvertToByteArray();
        }

        private void ConvertToByteArray()
        {
            Wildcards = new List<int>();

            string[] bytes = String.Split(' ');
            Bytes = new byte[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                string b = bytes[i];
                if (b == "??")
                {
                    Wildcards.Add(i);
                    Bytes[i] = 0xFF;
                } else
                {
                    Bytes[i] = byte.Parse(b, System.Globalization.NumberStyles.HexNumber);
                }
            }
        }

        public override bool Equals(object obj)
        {
            byte[] other = (byte[])obj;

            foreach (int index in Wildcards)
            {
                other[index] = 0xFF;
            }

            return Win32.memcmp(Bytes, other, Length) == 0;
        }

    }
}
