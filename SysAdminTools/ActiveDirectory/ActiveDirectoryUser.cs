using System.DirectoryServices;

namespace XyloCode.SysAdminTools.ActiveDirectory
{
    public class ActiveDirectoryUser
    {
        readonly SearchResult item;
        public ActiveDirectoryUser(SearchResult item)
        {
            this.item = item;

        }

        public string UserPrincipalName => this["userprincipalname"];
        public string Name => this["name"];
        public string Phone => this["telephonenumber"];
        public string Email => this["mail"];

        public string this[string name]
        {
            get
            {
                var v = item.Properties[name];
                if (v?.Count > 0)
                {
                    return v[0].ToString();
                }
                return null;
            }
        }
    }
}
