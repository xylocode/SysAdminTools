namespace XyloCode.SysAdminTools.MikroTik
{
    [MikroTikCommand("/certificate/export-certificate")]
    public class ExportCertificateCmd
    {
        public string Numbers { get; set; }
        public string ExportPassphrase { get; set; }
        public string FileName { get; set; }
        public string Type { get; set; }
    }
}
