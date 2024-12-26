using PasswordGenerator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using XyloCode.SysAdminTools.ActiveDirectory;
using XyloCode.SysAdminTools.MikroTik;

namespace XyloCode.SysAdminTools
{
    internal class Kiwi
    {
        readonly ActiveDirectoryClient ad;
        readonly MikroTikClient mikrotik;

        readonly PowerShell2 ps2 = new();
        readonly Password passGen = new(true, true, true, false, 16);


        public string LocalPath { get; init; }
        public string ActivatorPath { get; init; }
        public required string ActivatorWebSite { get; init; }

        public string Prefix { get; init; }
        public required string VpnConnectionName { get; set; }


        public required string Country { get; set; }
        public required string State { get; set; }
        public required string Locality { get; set; }
        public required string Organization { get; set; }
        public string Unit { get; set; }


        public required string Domain { get; init; }
        public string VpnSubdomain { get; init; } = "vpn";
        public required string CrlHost { get; init; }
        public string CaSubdomain { get; init; } = "vpn-ca";
     



        public string CertCaName => Prefix + "_CA";
        public string CertVpnName => Prefix + "_VPN";



        public List<ActiveDirectoryUser> Users { get; set; }


        public Kiwi(
            string localPath,
            string adServer,
            string adUser,
            string adPass,
            string mtHost,
            string mtUser,
            string mtPass)
        {
            LocalPath = localPath;
            ActivatorPath = $@"{localPath}\activator";
            Prefix = $"ikev2_{DateTime.Now:yyMMdd}";

            ad = new ActiveDirectoryClient(adServer, adUser, adPass);
            mikrotik = new MikroTikClient(mtHost, mtUser, mtPass);
        }

        public void Init()
        {
            if (!Directory.Exists(LocalPath))
                Directory.CreateDirectory(LocalPath);

            if (!Directory.Exists(ActivatorPath))
                Directory.CreateDirectory(ActivatorPath);
        }

        public void GenerateUserCertificates()
        {
            foreach (var user in Users)
            {
                Console.WriteLine(user.Name);    
                var indexOf = user.UserPrincipalName.IndexOf('@');
                var username = user
                    .UserPrincipalName[..indexOf];

                var userPath = LocalPath + @"\" + user.Name;
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);

                var passphrase = passGen.Next();
                
                var userCertName = CreateCertUser(username, passphrase);
                mikrotik.DownloadFileToFolder($"{userCertName}.p12", userPath);
                mikrotik.DownloadFileToFolder($"{CertVpnName}.crt", userPath);

                var activatorGuid = CreateActivator(passphrase, username, userPath);
                CreateScriptPS1(userPath, user, username, activatorGuid);
                CreateScriptCmd(userPath);
                Console.WriteLine("Done!");
                Console.WriteLine();

            }
        }

        public void Close()
        {
            ad.Dispose();
            mikrotik.Dispose();
        }

        public void SetUsersFromAD(string filter)
        {
            Users = ad.GetUsers(filter).ToList();
        }

        public void CreateCertCA()
        {
            var addCaCert = new AddCertificateCmd
            {
                Name = CertCaName,
                Country = Country,
                State = State,
                Locality = Locality,
                Organization = Organization,
                Unit = Unit,
                CommonName = $"{CaSubdomain}.{Domain}",
                SubjectAltName = $"DNS:{CaSubdomain}.{Domain}",
                KeyUsage = "digital-signature,key-encipherment,data-encipherment,key-cert-sign,crl-sign,tls-client,tls-server",
            };
            mikrotik.ExecuteNonQuery(addCaCert);

            var signCaCert = new SignCertificateCmd
            {
                Number = CertCaName,
                CaCrlHost = CrlHost,
            };
            mikrotik.ExecuteListWithDuration(signCaCert);

            var exportCaCert = new ExportCertificateCmd
            {
                Numbers = CertCaName,
                FileName = CertCaName,
                Type = "pem",
            };
            mikrotik.ExecuteNonQuery(exportCaCert);
        }

        public void CreateCertVPN()
        {
            var addVpnCert = new AddCertificateCmd
            {
                Name = CertVpnName,
                Country = Country,
                State = State,
                Locality = Locality,
                Organization = Organization,
                Unit = Unit,
                CommonName = $"{VpnSubdomain}.{Domain}",
                SubjectAltName = $"DNS:{VpnSubdomain}.{Domain}",
                KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-server",
            };
            mikrotik.ExecuteNonQuery(addVpnCert);

            var signVpnCert = new SignCertificateCmd
            {
                Number = CertVpnName,
                Ca = CertCaName,
                CaCrlHost = CrlHost,
            };
            mikrotik.ExecuteListWithDuration(signVpnCert);
        }

        public string CreateCertUser(string username, string passphrase)
        {
            string name = Prefix + "_user_" + username;

            var addUserCert = new AddCertificateCmd
            {
                Name = name,
                Country = Country,
                State = State,
                Locality = Locality,
                Organization = Organization,
                Unit = Unit,
                CommonName = $"{username}@{VpnSubdomain}.{Domain}",
                SubjectAltName = $"Email:{username}@{VpnSubdomain}.{Domain}",
                KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-client",
            };
            mikrotik.ExecuteNonQuery(addUserCert);

            var signUserCert = new SignCertificateCmd
            {
                Number = name,
                Ca = CertCaName,
                CaCrlHost = CrlHost,
            };
            mikrotik.ExecuteListWithDuration(signUserCert);

            var exportUserCert = new ExportCertificateCmd
            {
                Numbers = name,
                FileName = name,
                ExportPassphrase = passphrase,
                Type = "pkcs12",
            };
            mikrotik.ExecuteNonQuery(exportUserCert);

            return name;
        }

        public string CreateActivator(string passphrase, string username, string userPath)
        {
            var guid = Guid.NewGuid().ToString().ToUpper();
            var activator = ps2.Encrypt(passphrase, out string activatorKey);
            File.AppendAllText($@"{ActivatorPath}\{guid}.txt", activatorKey);
            File.AppendAllText($@"{userPath}\{Prefix}_user_{username}.dat", activator);
            return guid;
        }
    
        public void CreateScriptPS1(string userPath, ActiveDirectoryUser user, string username, string activatorGuid)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<#");
            sb.AppendLine(user.UserPrincipalName);
            sb.AppendLine(user.Name);

            if (!string.IsNullOrWhiteSpace(user.Email))
                sb.AppendLine(user.Email);

            if (!string.IsNullOrWhiteSpace(user.Phone))
                sb.AppendLine(user.Phone);

            sb.AppendLine(@"#>
#Requires -RunAsAdministrator

$vpn_name = \'" + VpnConnectionName + @"\';
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
$res = Invoke-WebRequest -Uri '{ActivatorWebSite}/{activatorGuid}.txt';
if($req.StatusCode -le 299) {{
        $set = ConvertTo-SecureString -String $res.Content -AsPlainText -Force;
    }} else {{
        $set = Read-Host -AsSecureString -Prompt 'Please enter the activation key for {activatorGuid}:';
    }}
}} catch {{
    $set = Read-Host -AsSecureString -Prompt 'Please enter the activation key for {activatorGuid}:';
}}
$k = Get-Content '{Prefix}_user_{username}.dat' | ConvertTo-SecureString -SecureKey $set;


$caParams = @{{
    FilePath = '{CertCaName}.crt';
    CertStoreLocation = 'Cert:\LocalMachine\Root';
}};

$pfxParams = @{{
    FilePath = '{Prefix}_user_{username}.p12';
    CertStoreLocation = 'Cert:\LocalMachine\My';
    Password = $k;
}};

$ca = Import-Certificate @caParams;
Import-PfxCertificate @pfxParams;

$vpnParams = @{{
    Name = $vpn_name;
    ServerAddress = '{VpnSubdomain}.{Domain}';
    AuthenticationMethod = 'MachineCertificate';
    MachineCertificateIssuerFilter = $ca[0];
    #MachineCertificateEKUFilter = ('1.3.6.1.5.5.7.3.6', '1.3.6.1.5.5.7.3.7');
    DnsSuffix = '{Domain}';
    EncryptionLevel = 'Maximum';
    TunnelType = 'Ikev2';
    SplitTunneling = $true;
}};

$ipsecParams = @{{
    AuthenticationTransformConstants = 'SHA256128';
    CipherTransformConstants = 'AES256';
    ConnectionName = $vpn_name;
    DHGroup = 'Group14';
    EncryptionMethod = 'AES256';
    IntegrityCheckMethod = 'SHA256';
    PfsGroup = 'None';
}};

Add-VpnConnection @vpnParams;
Set-VpnConnectionIPsecConfiguration @ipsecParams;

[console]::Beep();
[console]::WriteLine('The end!');
[console]::ReadLine();
");

            File.AppendAllText($@"{userPath}\install.ps1", sb.ToString(), Encoding.Default);
        }

        public void CreateScriptCmd(string userPath)
        {
            var cmd = $"powershell.exe -ExecutionPolicy RemoteSigned -NoLogo -File install.ps1";
            File.AppendAllText($@"{userPath}\install.cmd", cmd);
        }
    }
}
