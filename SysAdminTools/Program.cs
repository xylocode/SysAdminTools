using PasswordGenerator;
using System;
using System.IO;
using System.Linq;
using System.Text;
using XyloCode.SysAdminTools.ActiveDirectory;
using XyloCode.SysAdminTools.MikroTik;

namespace XyloCode.SysAdminTools
{
    internal class Program
    {
        static void Main(string[] args)
        {
            GenerateCertificates();
            Console.WriteLine("==---the end---==");
            Console.Beep();
            Console.ReadLine();
        }

        public static void GenerateCertificates()
        {
            const string localPath = @"c:\data\vpn";
            var ad = new ActiveDirectoryClient("ad.example.com", @"adUserName", @"adPassword");
            var mikrotik = new MikroTikClient("192.168.88.1", "apiUserName", @"apiPassword");
            var ps2 = new PowerShell2();
            var passGen = new Password(true, true, true, false, 16);

            if (!Directory.Exists(localPath))
            {
                Directory.CreateDirectory(localPath);
            }


            var users = ad.GetUsers(@"(&(objectclass=user)(MemberOf=CN=MyTargetGroupName,CN=Users,DC=example,DC=com))").ToList();

            var prefix = $"ikev2_{DateTime.Now:yyMMdd}_";
            var addCaCert = new AddCertificateCmd
            {
                Name = prefix + "CA",
                Country = "RU",
                State = "RegionCode",
                Locality = "CityName",
                Organization = "OrganizationNumber",
                Unit = "InnNumber",
                CommonName = "vpn-ca.example.com",
                SubjectAltName = "DNS:vpn-ca.example.com",
                KeyUsage = "digital-signature,key-encipherment,data-encipherment,key-cert-sign,crl-sign,tls-client,tls-server",
            };
            mikrotik.ExecuteNonQuery(addCaCert);

            var signCaCert = new SignCertificateCmd
            {
                Number = addCaCert.Name,
                CaCrlHost = "vpn-crl.example.com"
            };
            mikrotik.ExecuteListWithDuration(signCaCert);

            var addVpnCert = new AddCertificateCmd
            {
                Name = prefix + "VPN",
                Country = "RU",
                State = "RegionCode",
                Locality = "CityName",
                Organization = "OrganizationNumber",
                Unit = "InnNumber",
                CommonName = "vpn.example.com",
                SubjectAltName = "DNS:vpn.example.com",
                KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-client,tls-server",
            };
            mikrotik.ExecuteNonQuery(addVpnCert);

            var signVpnCert = new SignCertificateCmd
            {
                Number = addVpnCert.Name,
                Ca = addCaCert.Name,
                CaCrlHost = "vpn-crl.example.com"
            };
            mikrotik.ExecuteListWithDuration(signVpnCert);

            var ipsecIdentityCfg = new SetIPSecIdentityCmd
            {
                Numbers = "vpn",
                Certificate = addVpnCert.Name
            };
            mikrotik.ExecuteNonQuery(ipsecIdentityCfg);

            var exportCaCert = new ExportCertificateCmd
            {
                Numbers = addCaCert.Name,
                FileName = addCaCert.Name,
                Type = "pem",
            };
            mikrotik.ExecuteNonQuery(exportCaCert);
            mikrotik.DownloadFile(exportCaCert.FileName + ".crt", localPath + @"\" + exportCaCert.FileName + ".crt");

            foreach (var user in users)
            {
                Console.WriteLine(user.Name);
                var indexOf = user.UserPrincipalName.IndexOf('@');
                var username = user
                    .UserPrincipalName[..indexOf]
                    .Replace(".", "")
                    .Replace("_", "")
                    .Replace("-", "");


                var userPath = localPath + @"\" + user.Name;
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);

                var passphrase = passGen.Next();
                

                var addUserCert = new AddCertificateCmd
                {
                    Name = prefix + "user_" + username,
                    Country = "RU",
                    State = "RegionCode",
                    Locality = "CityName",
                    Organization = "OrganizationNumber",
                    Unit = "InnNumber",
                    CommonName = $"{username}.vpn.example.com",
                    SubjectAltName = $"DNS:{username}.vpn.example.com",
                    KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-client",
                };
                mikrotik.ExecuteNonQuery(addUserCert);

                var signUserCert = new SignCertificateCmd
                {
                    Number = addUserCert.Name,
                    Ca = addCaCert.Name,
                    CaCrlHost = "vpn-crl.example.com"
                };
                mikrotik.ExecuteListWithDuration(signUserCert);

                var exportUserCert = new ExportCertificateCmd
                {
                    Numbers = addUserCert.Name,
                    FileName = addUserCert.Name,
                    ExportPassphrase = passphrase,
                    Type = "pkcs12",
                };
                mikrotik.ExecuteNonQuery(exportUserCert);

                var guid = Guid.NewGuid().ToString();
                var activator = ps2.Encrypt(passphrase, out string activatorKey);
                File.AppendAllText($@"{localPath}\activator\{guid}.txt", activatorKey);
                File.AppendAllText($@"{userPath}\{addUserCert.Name}.dat", activator);


                var sb = new StringBuilder();
                sb.AppendLine("<#");
                sb.AppendLine(user.UserPrincipalName);
                sb.AppendLine(user.Name);

                if (!string.IsNullOrWhiteSpace(user.Email))
                    sb.AppendLine(user.Email);

                if (!string.IsNullOrWhiteSpace(user.Phone))
                    sb.AppendLine(user.Phone);

                sb.AppendLine(@"#>
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file ""{0}"" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}");
                sb.AppendLine(@"
# BEGIN
$vpn_name = 'example_ikev2_vpn';
$exists_vpn = Get-VpnConnection -AllUserConnection
foreach($vpn in $exists_vpn) {
    if($vpn.Name -eq $vpn_name) {
        Remove-VpnConnection -Name $vpn_name -AllUserConnection;
    }
}

$exists_vpn = Get-VpnConnection
foreach($vpn in $exists_vpn) {
    if($vpn.Name -eq $vpn_name) {
        Remove-VpnConnection -Name $vpn_name;
    }
}
");
                

                sb.AppendLine(@$"
try {{
$res = Invoke-WebRequest -Uri 'https://example.com/vpn/activator/{guid}.txt';
if($req.StatusCode -eq 200) {{
        $set = ConvertTo-SecureString -String $res.Content -AsPlainText -Force;
    }} else {{
        $set = Read-Host -AsSecureString -Prompt 'Please enter the activation key for {guid}:';
    }}
}} catch {{
    $set = Read-Host -AsSecureString -Prompt 'Please enter the activation key for {guid}:';
}}
$pwd = Get-Content '{exportUserCert.FileName}.dat' | ConvertTo-SecureString -SecureKey $set;
Import-Certificate -FilePath '{exportCaCert.FileName}.crt' -CertStoreLocation 'Cert:\LocalMachine\Root';
Import-PfxCertificate -FilePath '{exportUserCert.FileName}.p12' -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pwd;
Add-VpnConnection -Name $vpn_name -ServerAddress vpn.example.com c -AuthenticationMethod MachineCertificate -DnsSuffix example.com -EncryptionLevel Maximum -TunnelType Ikev2 -SplitTunneling;
Set-VpnConnectionIPsecConfiguration -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -ConnectionName $vpn_name -DHGroup Group14 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -PfsGroup None;
");

                var scriptName = userPath + @"\example_" + addUserCert.Name + ".ps1";
                File.AppendAllText(scriptName, sb.ToString(), Encoding.Default);
                ps2.Ps2Exe(scriptName, false);

                mikrotik.DownloadFile(exportCaCert.FileName + ".crt", userPath + @"\" + exportCaCert.FileName + ".crt");
                mikrotik.DownloadFile(exportUserCert.FileName + ".p12", userPath + @"\" + exportUserCert.FileName + ".p12");
            }

            ad.Dispose();
            mikrotik.Dispose();
        }
    }
}