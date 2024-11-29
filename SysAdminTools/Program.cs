﻿using PasswordGenerator;
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
            Console.Beep();
            Console.ReadLine();
        }

        public static void GenerateCertificates()
        {
            const string localPath = @"c:\data\vpn";
            var ad = new ActiveDirectoryClient("ad.example.com", @"adUserName", @"adPassword");
            var mikrotik = new MikroTikClient("192.168.88.1", "apiUserName", @"apiPassword");
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
                var indexOf = user.UserPrincipalName.IndexOf("@");
                var username = user
                    .UserPrincipalName[..indexOf]
                    .Replace(".", "")
                    .Replace("_", "")
                    .Replace("-", "");

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

                var userPath = localPath + @"\" + user.Name;
                if (!Directory.Exists(userPath))
                    Directory.CreateDirectory(userPath);
                var sb = new StringBuilder();
                sb.AppendLine(user.UserPrincipalName);
                sb.AppendLine(user.Name);

                if (!string.IsNullOrWhiteSpace(user.Email))
                    sb.AppendLine(user.Email);

                if (!string.IsNullOrWhiteSpace(user.Phone))
                    sb.AppendLine(user.Phone);

                sb.AppendLine("=-=-=-=-=");
                sb.AppendLine(passphrase);
                File.AppendAllText(userPath + @"\" + addUserCert.Name + "_password.txt", sb.ToString());
                mikrotik.DownloadFile(exportUserCert.FileName + ".p12", userPath + @"\" + exportUserCert.FileName + ".p12");
            }

            ad.Dispose();
            mikrotik.Dispose();
        }
    }
}