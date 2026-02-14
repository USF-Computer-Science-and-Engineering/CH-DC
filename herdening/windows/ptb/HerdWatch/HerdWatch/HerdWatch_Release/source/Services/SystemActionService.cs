using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics;

namespace HerdWatch.Services;

public class SystemActionService
{
    private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";

    public async Task<bool> SinkholeDomain(string domain)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;

            // Basic validation to prevent injection or invalid filenames
            if (domain.Any(c => Path.GetInvalidFileNameChars().Contains(c)) && domain != "localhost") 
                return false;

            var lines = await File.ReadAllLinesAsync(HostsPath);
            
            // Check if already sinkholed
            if (lines.Any(l => l.Trim().EndsWith(domain, StringComparison.OrdinalIgnoreCase) && l.Trim().StartsWith("0.0.0.0") || l.Trim().StartsWith("127.0.0.1")))
            {
                return true; // Already done
            }

            using (var writer = File.AppendText(HostsPath))
            {
                await writer.WriteLineAsync($"\n# HerdWatch Sinkhole {DateTime.Now}");
                await writer.WriteLineAsync($"0.0.0.0 {domain}");
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sinkholing domain: {ex.Message}");
            return false;
        }
    }

    public async Task<List<string>> GetSinkholedDomains()
    {
        var domains = new List<string>();
        try
        {
            if (!File.Exists(HostsPath)) return domains;

            var lines = await File.ReadAllLinesAsync(HostsPath);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                // Look for our specific signature or just uncommmented lines pointing to loopback
                if (trimmed.StartsWith("#")) continue;
                
                if (trimmed.StartsWith("127.0.0.1") || trimmed.StartsWith("0.0.0.0"))
                {
                    // Basic parsing: 127.0.0.1 example.com ...
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        var domain = parts[1];
                        if (domain != "localhost" && domain != "host.docker.internal")
                        {
                            domains.Add(domain);
                        }
                    }
                }
            }
        }
        catch { }
        return domains.Distinct().OrderBy(x => x).ToList();
    }

    public async Task<bool> RemoveSinkhole(string domain)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;

            var lines = (await File.ReadAllLinesAsync(HostsPath)).ToList();
            var newLines = new List<string>();
            var modified = false;

            for (int i = 0; i < lines.Count; i++)
            {
                var line = lines[i];
                var trimmed = line.Trim();

                // Check if this line blocks the domain
                bool isBlock = (trimmed.StartsWith("127.0.0.1") || trimmed.StartsWith("0.0.0.0")) && 
                               trimmed.Contains(domain, StringComparison.OrdinalIgnoreCase);
                
                // Also check strict parsing to avoid partial matches (e.g. google.com vs google.com.br)
                if (isBlock)
                {
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && parts[1].Equals(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        modified = true;
                        continue; // Skip this line (remove it)
                    }
                }

                // Also remove the specific comment line if we added it? 
                // Our sinkhole logic adds: \n# HerdWatch Sinkhole ...\n0.0.0.0 domain
                // It might be hard to pair them up perfectly without more logic, but removing the block is the critical part.
                // We'll just keep simple for now.
                
                newLines.Add(line);
            }

            if (modified)
            {
                await File.WriteAllLinesAsync(HostsPath, newLines);
                FlushDns();
                return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error removing sinkhole: {ex.Message}");
            return false;
        }
    }

    private void FlushDns()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "ipconfig",
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }
        catch { }
    }
}
