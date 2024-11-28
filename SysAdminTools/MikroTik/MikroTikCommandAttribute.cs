using System;

namespace XyloCode.SysAdminTools.MikroTik
{
    [AttributeUsage(AttributeTargets.Class)]
    public class MikroTikCommandAttribute(string name) : Attribute
    {
        public string Name { get; set; } = name;
    }
}