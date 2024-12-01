using PasswordGenerator;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace XyloCode.SysAdminTools
{
    internal class PowerShell2
    {
        readonly PowerShell ps;
        readonly Password pwd;

        public PowerShell2()
        {
            var iss = InitialSessionState.CreateDefault2();
            iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
            ps = PowerShell.Create(iss);
            //ps.AddCommand("Import-Module").AddParameter("name", "ps2exe").Invoke();

            pwd = new(true, true, true, true, 16);
        }


        public string Encrypt(string plainText,  out string key)
        {
            key = pwd.Next();
            var script = ps.AddScript($@"
$secureKey = ConvertTo-SecureString -String '{key}' -AsPlainText -Force;
$secureText = ConvertTo-SecureString -String '{plainText}' -AsPlainText -Force;
$result = ConvertFrom-SecureString -SecureString $secureText -SecureKey $secureKey;
$result
");

            return script
                .Invoke()
                .First()
                .ToString();
        }

        public Collection<PSObject> Ps2Exe(string ps1File, bool deleteAfter = false)
        {
            var indexOf = ps1File.LastIndexOf(".ps1");
            var res = ps.AddCommand("Invoke-ps2exe", false)
                .AddParameter("inputFile", ps1File)
                .AddParameter("outputFile", ps1File[..indexOf] + ".exe")
                .AddParameter("requireAdmin")
                .Invoke();

            if (deleteAfter)
            {
                File.Delete(ps1File);
            }
            return res;
        }
    }
}
