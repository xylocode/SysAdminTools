namespace XyloCode.SysAdminTools.MikroTik
{
    [MikroTikCommand("/ip/ipsec/identity/set")]
    internal class SetIPSecIdentityCmd
    {
        public string Numbers { get; set; }
        public string AuthMethod { get; set; }
        public string Certificate { get; set; }
        public string Comment { get; set; }
        public string Disabled { get; set; }
        public string EapMethods { get; set; }
        public string GeneratePolicy { get; set; }
        public string Key { get; set; }
        public string MatchBy { get; set; }
        public string ModeConfig { get; set; }
        public string MyId { get; set; }
        public string NotrackChain { get; set; }
        public string Password { get; set; }
        public string Peer { get; set; }
        public string PolicyTemplateGroup { get; set; }
        public string RemoteCertificate { get; set; }
        public string RemoteId { get; set; }
        public string RemoteKey { get; set; }
        public string Secret { get; set; }
        public string Username { get; set; }
    }
}
