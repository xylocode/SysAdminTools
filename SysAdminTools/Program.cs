using System;

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
            var kiwi = new Kiwi(
                localPath: "",
                adServer: "",
                adUser: "",
                adPass: "",
                mtHost: "",
                mtUser: "",
                mtPass: "")
            {
                Country = "SU",
                State = "",
                Locality = "",
                Organization = "",
                Unit = "",

                ActivatorWebSite = @"",

                Prefix = "ikev2_241202",
                VpnConnectionName = "example_ikev2_vpn",

                Domain = "example.com",
                CrlHost = "vpn-crl.example.com",

            };
            kiwi.Init();
            kiwi.SetUsersFromAD(filter: "(&(objectclass=user)(MemberOf=CN=MyTargetGroupName,CN=Users,DC=example,DC=ru))");
            kiwi.GenerateUserCertificates();
            kiwi.Close();
        }
    }
}