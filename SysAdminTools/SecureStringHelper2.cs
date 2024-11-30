using PasswordGenerator;
using System.Linq;
using System.Management.Automation;

namespace XyloCode.SysAdminTools
{
    internal static class SecureStringHelper2
    {
        static readonly Password pwd = new(true, true, true, true, 16);
        public static string Encrypt(string plainText,  out string key)
        {
            key = pwd.Next();
            var ps = PowerShell.Create();
            var res = ps.AddScript($@"
$secureKey = ConvertTo-SecureString -String '{key}' -AsPlainText -Force;
$secureText = ConvertTo-SecureString -String '{plainText}' -AsPlainText -Force;
$result = ConvertFrom-SecureString -SecureString $secureText -SecureKey $secureKey;
$result
", true).Invoke();

            return res
                .First()
                .ToString();
        }
    }
}
