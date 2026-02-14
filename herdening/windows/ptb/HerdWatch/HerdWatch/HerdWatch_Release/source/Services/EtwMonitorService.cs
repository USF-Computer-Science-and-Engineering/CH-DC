
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Hosting;
using HerdWatch.Models;

namespace HerdWatch.Services;

public class EtwMonitorService : BackgroundService
{
    private static readonly Guid DnsClientProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private readonly HerdWatchConfig _config;
    private TraceEventSession? _session;
    private SqliteConnection? _sqliteConn;
    private SqliteCommand? _insertCmd;
    private readonly object _dbLock = new();
    
    // Parameters
    private SqliteParameter? _pTimestamp;
    private SqliteParameter? _pEventType;
    private SqliteParameter? _pEventId;
    private SqliteParameter? _pProcessId;
    private SqliteParameter? _pProcessName;
    private SqliteParameter? _pQueryName;
    private SqliteParameter? _pQueryType;
    private SqliteParameter? _pStatus;
    private SqliteParameter? _pQueryResults;
    private SqliteParameter? _pDnsServer;
    private SqliteParameter? _pInterfaceIndex;

    public EtwMonitorService(HerdWatchConfig config)
    {
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var dbFile = new FileInfo(_config.DbPath);
        dbFile.Directory?.Create();

        InitDatabase();

        var sessionName = $"HerdWatch_{Environment.ProcessId}";

        try
        {
            using var oldSession = TraceEventSession.GetActiveSession(sessionName);
            oldSession?.Stop();
        }
        catch { }

        try
        {
            _session = new TraceEventSession(sessionName);
            _session.Source.Dynamic.All += ProcessEvent;
            
            // This is where 0x800705AA usually happens if too many sessions exist
            _session.EnableProvider(DnsClientProviderGuid, TraceEventLevel.Verbose, ulong.MaxValue);
            
            Console.WriteLine($"HerdWatch started - Monitoring DNS activity");
            
            var processingTask = Task.Run(() => _session.Source.Process(), stoppingToken);
            
            try
            {
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }

            _session.Stop();
            await processingTask;
            return; // Exit normally
        }
        catch (System.Runtime.InteropServices.COMException ex) when ((uint)ex.HResult == 0x800705AA)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[CRITICAL ERROR] Insufficient system resources to start ETW session.");
            Console.WriteLine("This usually means there are too many active ETW sessions on your system.");
            Console.WriteLine("\nTo fix this, please run the following command in an Administrator terminal:");
            Console.WriteLine($"   logman stop \"{sessionName}\" -ets");
            Console.WriteLine("   logman stop \"HerdWatch\" -ets");
            Console.WriteLine("\nOr list all sessions to find zombies:");
            Console.WriteLine("   logman query -ets");
            Console.ResetColor();
            
            // Allow the application to stay alive so the user can read the message, 
            // but the background service is effectively dead.
            // In a real scenario we might want to kill the app, but let's just wait a bit.
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            throw; // Re-throw to crash properly if needed or just let it die
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[ERROR] Failed to start ETW session: {ex.Message}");
            Console.ResetColor();
            throw;
        }


    }

    private void InitDatabase()
    {
        _sqliteConn = new SqliteConnection($"Data Source={_config.DbPath}");
        _sqliteConn.Open();

        using (var cmd = new SqliteCommand("PRAGMA journal_mode=WAL", _sqliteConn))
            cmd.ExecuteNonQuery();

        var createTable = @"
            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT,
                event_id INTEGER,
                process_id INTEGER,
                process_name TEXT,
                query_name TEXT,
                query_type TEXT,
                status TEXT,
                query_results TEXT,
                dns_server TEXT,
                interface_index INTEGER,
                UNIQUE(timestamp, process_id, query_name, query_type, status) ON CONFLICT IGNORE
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_process ON dns_events(process_id, process_name);
            CREATE INDEX IF NOT EXISTS idx_query ON dns_events(query_name);
        ";

        using (var cmd = new SqliteCommand(createTable, _sqliteConn))
            cmd.ExecuteNonQuery();

        _insertCmd = new SqliteCommand(@"
            INSERT INTO dns_events (timestamp, event_type, event_id, process_id, process_name, query_name, query_type, status, query_results, dns_server, interface_index)
            VALUES (@timestamp, @event_type, @event_id, @process_id, @process_name, @query_name, @query_type, @status, @query_results, @dns_server, @interface_index)
        ", _sqliteConn);

        _pTimestamp = _insertCmd.Parameters.Add("@timestamp", SqliteType.Text);
        _pEventType = _insertCmd.Parameters.Add("@event_type", SqliteType.Text);
        _pEventId = _insertCmd.Parameters.Add("@event_id", SqliteType.Integer);
        _pProcessId = _insertCmd.Parameters.Add("@process_id", SqliteType.Integer);
        _pProcessName = _insertCmd.Parameters.Add("@process_name", SqliteType.Text);
        _pQueryName = _insertCmd.Parameters.Add("@query_name", SqliteType.Text);
        _pQueryType = _insertCmd.Parameters.Add("@query_type", SqliteType.Text);
        _pStatus = _insertCmd.Parameters.Add("@status", SqliteType.Text);
        _pQueryResults = _insertCmd.Parameters.Add("@query_results", SqliteType.Text);
        _pDnsServer = _insertCmd.Parameters.Add("@dns_server", SqliteType.Text);
        _pInterfaceIndex = _insertCmd.Parameters.Add("@interface_index", SqliteType.Integer);

        _insertCmd.Prepare();
    }

    private void ProcessEvent(TraceEvent evt)
    {
        if (evt.ID == 0) return;

        var processId = evt.ProcessID;
        var processName = GetProcessName(processId);
        var queryName = evt.PayloadByName("QueryName")?.ToString()?.TrimEnd('.');

        if (string.IsNullOrEmpty(queryName)) return;

        var qtypeVal = evt.PayloadByName("QueryType");
        string? queryType = null;
        if (qtypeVal != null && int.TryParse(qtypeVal.ToString()?.Trim(), out int qt))
        {
            queryType = GetQueryTypeName(qt);
        }

        var statusVal = evt.PayloadByName("Status") ?? evt.PayloadByName("QueryStatus");
        string? status = null;
        if (statusVal != null)
        {
            if (int.TryParse(statusVal.ToString()?.Trim(), out int st))
            {
                status = GetStatusName(st);
            }
            else
            {
                status = statusVal.ToString();
            }
        }

        var queryResults = evt.PayloadByName("QueryResults")?.ToString();
        var dnsServer = evt.PayloadByName("DNSServerAddress")?.ToString();

        var ifIdxVal = evt.PayloadByName("InterfaceIndex");
        int? interfaceIndex = null;
        if (ifIdxVal != null && int.TryParse(ifIdxVal.ToString()?.Trim(), out int idx))
            interfaceIndex = idx;

        try
        {
            lock (_dbLock)
            {
                if (_insertCmd == null) return;
                
                _pTimestamp!.Value = evt.TimeStamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff");
                _pEventType!.Value = GetEventName((int)evt.ID);
                _pEventId!.Value = (int)evt.ID;
                _pProcessId!.Value = processId;
                _pProcessName!.Value = (object?)processName ?? DBNull.Value;
                _pQueryName!.Value = (object?)queryName ?? DBNull.Value;
                _pQueryType!.Value = (object?)queryType ?? DBNull.Value;
                _pStatus!.Value = (object?)status ?? DBNull.Value;
                _pQueryResults!.Value = (object?)queryResults ?? DBNull.Value;
                _pDnsServer!.Value = (object?)dnsServer ?? DBNull.Value;
                _pInterfaceIndex!.Value = (object?)interfaceIndex ?? DBNull.Value;

                _insertCmd.ExecuteNonQuery();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error inserting event: {ex.Message}");
            Console.WriteLine($"DEBUG Params: Time={evt.TimeStamp}, PID={processId}, Name={processName}, Q={queryName}, S={status}");
        }
    }

    private string GetProcessName(int pid)
    {
        if (pid <= 0) return "?";
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch
        {
            return $"PID:{pid}";
        }
    }

    private string GetQueryTypeName(int type)
    {
        return type switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            37 => "CERT",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            50 => "NSEC3",
            51 => "NSEC3PARAM",
            249 => "TKEY",
            250 => "TSIG",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            99 => "SPF",
            255 => "ANY",
            257 => "CAA",
            _ => $"TYPE{type}"
        };
    }

    private string GetStatusName(int status)
    {
        return status switch
        {
            0 => "OK",
            87 => "Cached",
            1168 => "NotFound",
            1214 => "InvalidName",
            1460 => "Timeout",
            9002 => "ServFail",
            9003 => "NXDomain",
            9004 => "NotImpl",
            9005 => "Refused",
            9501 => "NoRecords",
            9560 => "Timeout",
            9701 => "NoRecord",
            9702 => "RecordFormat",
            11001 => "HostNotFound",
            11002 => "TryAgain",
            11003 => "NoRecovery",
            11004 => "NoData",
            _ => $"STATUS{status}"
        };
    }

    private string GetEventName(int eventId)
    {
        return eventId switch
        {
            1001 => "SERVER_LIST",
            1015 => "SERVER_TIMEOUT",
            1016 => "NAME_ERROR",
            3006 => "QUERY",
            3008 => "COMPLETE",
            3009 => "SEND",
            3010 => "SEND_TO",
            3011 => "RECV",
            3016 => "CACHE_LOOKUP",
            3018 => "CACHE",
            3019 => "WIRE_QUERY",
            3020 => "RESPONSE",
            _ => $"EVENT_{eventId}"
        };
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _session?.Stop();
        _insertCmd?.Dispose();
        _sqliteConn?.Dispose();

        await base.StopAsync(cancellationToken);
    }
}
