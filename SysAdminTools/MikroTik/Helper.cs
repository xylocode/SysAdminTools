using System.Linq;
using System.Reflection;
using tik4net;

namespace XyloCode.SysAdminTools.MikroTik
{
    public static class Helper
    {
        public static void Parameterize<T>(this ITikCommand cmd, T obj)
            where T : class
        {
            var props = typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public);
            foreach (var prop in props)
            {
                var value = prop.GetValue(obj);
                if (value != null)
                {
                    cmd.WithParameter(prop.Name.ToMikroTikCase(), value.ToString());
                }
            }
        }

        public static string ToMikroTikCase(this string str)
        {
            return string.Concat(str.Select((x, i) => i > 0 && char.IsUpper(x) ? "-" + x.ToString() : x.ToString())).ToLower();
        }
    }
}
