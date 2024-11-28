using FluentFTP;
using System;
using System.Net;
using System.Reflection;
using tik4net;

namespace XyloCode.SysAdminTools.MikroTik
{
    public class MikroTikClient : IDisposable
    {
        private readonly ITikConnection mikrotik;
        private readonly FtpClient ftpClient;
        public MikroTikClient(string host, string mtUser, string mtPass)
        {
            mikrotik = ConnectionFactory.CreateConnection(TikConnectionType.Api);
            mikrotik.Open(host, mtUser, mtPass);

            var nc = new NetworkCredential(mtUser, mtPass);
            ftpClient = new FtpClient(host, nc, 21);
            ftpClient.Connect();
        }

        public void Dispose()
        {
            Close();
        }

        public void Close()
        {
            mikrotik.Close();
            ftpClient.Disconnect();
            ftpClient.Dispose();
        }

        public void ExecuteNonQuery<TCommandModel>(TCommandModel model)
            where TCommandModel : class
        {
            var cmdName = typeof(TCommandModel)
                .GetCustomAttribute<MikroTikCommandAttribute>()?.Name;
            if (string.IsNullOrWhiteSpace(cmdName))
                throw new Exception("Не задана комманда!");

            var cmd = mikrotik.CreateCommand(cmdName);
            cmd.Parameterize(model);
            cmd.ExecuteNonQuery();
        }

        public void DownloadFile(string fileName, string localPath)
        {
            ftpClient.DownloadFile(localPath, fileName);
        }
    }
}
