namespace XyloCode.SysAdminTools.MikroTik
{
    [MikroTikCommand("/certificate/add")]
    public class AddCertificateCmd
    {
        public string CommonName { get; set; }
        public string CopyFrom { get; set; }
        public string Country { get; set; } = "RU";
        public string DaysValid { get; set; } = "825";
        public string DigestAlgorithm { get; set; }
        public string KeySize { get; set; } = "2048";
        public string KeyUsage { get; set; }
        public string Locality { get; set; }
        public string Name { get; set; }
        public string Organization { get; set; }
        public string State { get; set; }
        public string SubjectAltName { get; set; }
        public string Trusted { get; set; }
        public string Unit { get; set; }
    }
}
