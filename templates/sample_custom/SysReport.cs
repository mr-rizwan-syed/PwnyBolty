// ============================================================
// SysReport — minimal local-write test for the Custom tab
// ============================================================
// Application Name in UI: SysReport
// Class: SysReportManager (must match)
// No network — writes a plain-text report to the Desktop.
// Verify by opening: %USERPROFILE%\Desktop\SysReport.txt
// ============================================================

using System;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class SysReportManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        if (!AppDomain.CurrentDomain.IsDefaultAppDomain()) return;
        new Thread(Run) { IsBackground = true }.Start();
    }

    private static void Run()
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== SysReport ===");
            sb.AppendLine("Time      : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Machine   : " + Environment.MachineName);
            sb.AppendLine("User      : " + Environment.UserName);
            sb.AppendLine("Domain    : " + Environment.UserDomainName);
            sb.AppendLine("OS        : " + Environment.OSVersion);
            sb.AppendLine("CLR       : " + Environment.Version);
            sb.AppendLine("CWD       : " + Environment.CurrentDirectory);
            sb.AppendLine("Profile   : " + Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

            // IPs
            sb.AppendLine();
            sb.AppendLine("--- IPs ---");
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in ni.GetIPProperties().UnicastAddresses)
                    if (a.Address.AddressFamily == AddressFamily.InterNetwork)
                        sb.AppendLine("  " + ni.Name + " : " + a.Address);

            // Processes
            sb.AppendLine();
            sb.AppendLine("--- Processes ---");
            foreach (var p in Process.GetProcesses())
                try { sb.AppendLine("  " + p.ProcessName + " (pid " + p.Id + ")"); } catch { }

            string dest = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "SysReport.txt");
            File.WriteAllText(dest, sb.ToString());
        }
        catch { }
    }
}
