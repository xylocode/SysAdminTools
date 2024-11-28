namespace XyloCode.SysAdminTools.MikroTik
{
    [MikroTikCommand("/certificate/sign")]
    public class SignCertificateCmd
    {
        public string Number { get; set; }
        public string Append { get; set; }
        public string AsValue { get; set; }
        public string Ca { get; set; }
        public string CaCrlHost { get; set; }
        public string CaOnSmartCard { get; set; }
        public string Do { get; set; }
        public string Duration { get; set; }
        public string File { get; set; }
        public string Interval { get; set; }
        public string Name { get; set; }
        public string Once { get; set; }
        public string WithoutPaging { get; set; }
    }
}
