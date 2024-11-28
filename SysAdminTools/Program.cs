using PasswordGenerator;
using System;
using System.IO;
using System.Linq;
using System.Text;
using XyloCode.SysAdminTools.ActiveDirectory;
using XyloCode.SysAdminTools.MikroTik;

namespace SysAdminTools
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Beep();
            Console.ReadLine();
        }

        public static void GenerateCertificates()
        {
            const string localPath = @"C:\data\vpn";
            var ad = new ActiveDirectoryClient("ad.example.ru", "", "");
            var mikrotik = new MikroTikClient("172.24.128.1", "apiUser", @"eM7<mA8+yM0<eB5@aT8%");
            var passGen = new Password(true, true, true, false, 16);

            if (!Directory.Exists(localPath))
            {
                Directory.CreateDirectory(localPath);
            }
            

            var users = ad.GetUsers(@"(&(objectclass=user)(MemberOf=CN=RadiusConnection1,CN=Users,DC=example,DC=ru))").ToList();

            var prefix = $"ikev2_{DateTime.Now:yymmdd}_";
            var addCaCert = new AddCertificateCmd
            {
                Name = prefix + "CA",
                Country = "RU",
                State = "54",
                Locality = "Novosibirsk",
                Organization = "",
                Unit = "",
                CommonName = "vpn-ca.example.ru",
                SubjectAltName = "DNS:vpn-ca.example.ru",
                KeyUsage = "digital-signature,key-encipherment,data-encipherment,key-cert.-sign,crl-sign,tls-client,tls-server",
            };
            mikrotik.ExecuteNonQuery(addCaCert);

            var signCaCert = new SignCertificateCmd
            {
                Name = addCaCert.Name,
                CaCrlHost = "vpn-crl.example.ru"
            };
            mikrotik.ExecuteNonQuery(signCaCert);

            var addVpnCert = new AddCertificateCmd
            {
                Name = prefix + "VPN",
                Country = "RU",
                State = "54",
                Locality = "Novosibirsk",
                Organization = "",
                Unit = "",
                CommonName = "vpn.example.ru",
                SubjectAltName = "DNS:vpn.example.ru",
                KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-client,tls-server",
            };
            mikrotik.ExecuteNonQuery(addVpnCert);

            var signVpnCert = new SignCertificateCmd
            {
                Name = addVpnCert.Name,
                Ca = addCaCert.Name,
                CaCrlHost = "vpn-crl.example.ru"
            };
            mikrotik.ExecuteNonQuery(signVpnCert);

            var exportVpnCert = new ExportCertificateCmd
            {
                Numbers = addVpnCert.Name,
                FileName = addVpnCert.Name + ".crt",
                Type = "pem",
            };
            mikrotik.ExecuteNonQuery(exportVpnCert);
            mikrotik.DownloadFile(exportVpnCert.FileName, localPath);

            foreach (var user in users)
            {
                var indexOf = user.UserPrincipalName.IndexOf("@");
                var username = user
                    .UserPrincipalName[..indexOf]
                    .Replace(".", "")
                    .Replace("_", "");

                var passphrase = passGen.Next();


                var addUserCert = new AddCertificateCmd
                {
                    Name = prefix + "user_" + username,
                    Country = "RU",
                    State = "54",
                    Locality = "Novosibirsk",
                    Organization = "",
                    Unit = "",
                    CommonName = $"{username}.vpn.example.ru",
                    SubjectAltName = $"DNS:{username}.vpn.example.ru",
                    KeyUsage = "ipsec-user,ipsec-tunnel,ipsec-end-system,tls-client",
                };
                mikrotik.ExecuteNonQuery(addCaCert);

                var signUserCert = new SignCertificateCmd
                {
                    Name = addUserCert.Name,
                    Ca = addCaCert.Name,
                    CaCrlHost = "vpn-crl.example.ru"
                };
                mikrotik.ExecuteNonQuery(signUserCert);

                var exportUserCert = new ExportCertificateCmd
                {
                    Numbers = addUserCert.Name,
                    FileName = addUserCert.Name + ".p12",
                    ExportPassphrase = passphrase,
                    Type = "PKCS12",
                };
                mikrotik.ExecuteNonQuery(exportUserCert);

                var userPath = localPath + @"\" + user.Name;
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);
                var sb = new StringBuilder();
                sb.AppendLine(user.UserPrincipalName);
                sb.AppendLine(user.Name);
                sb.AppendLine(user.Email);
                sb.AppendLine(user.Phone);
                sb.AppendLine("=-=-=-=-=");
                sb.AppendLine(passphrase);
                File.AppendAllText(userPath + @"\" + addUserCert.Name + "_password.txt", sb.ToString());

                mikrotik.DownloadFile(exportUserCert.FileName, userPath);
            }
            
            ad.Dispose();
            mikrotik.Dispose();
        }
    }
}
