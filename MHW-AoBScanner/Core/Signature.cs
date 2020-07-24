using System;
using System.Collections.Generic;
using System.Text;

namespace MHW_AoBScanner.Core
{
    public class Signature
    {
        public string Name { get; set; }
        public Pattern Pattern { get; set; }
        public int Offset { get; set; }
        public bool Found { get; set; }
        public int Length => Pattern.Length;
    }
}
