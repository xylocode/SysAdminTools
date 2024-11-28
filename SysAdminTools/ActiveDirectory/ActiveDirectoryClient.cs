using System;
using System.Collections.Generic;
using System.DirectoryServices;

namespace XyloCode.SysAdminTools.ActiveDirectory
{
    public class ActiveDirectoryClient : IDisposable
    {
        private readonly DirectoryEntry adRoot;

        public ActiveDirectoryClient(string server, string adUser, string adPass)
        {
            adRoot = new DirectoryEntry("LDAP://" + server, adUser, adPass, AuthenticationTypes.Secure);
        }

        public void Dispose()
        {
            adRoot.Dispose();
        }


        /// <example>(&(objectclass=user)(MemberOf=CN=MyTargetGroup,CN=Users,DC=xylocode,DC=com))</example>
        public IEnumerable<ActiveDirectoryUser> GetUsers(string filter,
            SearchScope searchScope = SearchScope.Subtree,
            ReferralChasingOption referralChasing = ReferralChasingOption.All)
        {
            var searcher = new DirectorySearcher(adRoot)
            {
                SearchScope = searchScope,
                ReferralChasing = referralChasing,
                Filter = filter
            };
            searcher.PropertiesToLoad.AddRange(["userprincipalname", "name", "telephonenumber", "mail"]);
            SearchResultCollection result = searcher.FindAll();
            foreach (SearchResult item in result)
            {
                yield return new ActiveDirectoryUser(item);
            }
        }
    }
}
