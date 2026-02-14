
using System;
using System.Collections.Generic;

namespace HerdWatch.Models;

public class HerdWatchConfig
{
    public string DbPath { get; set; } = "";
    public bool EnableWebUI { get; set; } = true;
    public int WebPort { get; set; } = 5000;
    public int RetentionDays { get; set; } = 7;
}

public class ProcessSummary
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public long TotalQueries { get; set; }
    public double SuccessRate { get; set; }
    public double QueriesPerMinute { get; set; }
    public long DataVolume { get; set; }
    public long UniqueDomains { get; set; }
}

public class ProcessDetail
{
    public long TotalQueries { get; set; }
    public double SuccessRate { get; set; }
    public long UniqueDomains { get; set; }
}

public class LiveProcessData
{
    public List<ConnectionInfo> Connections { get; set; } = new();
    public List<DomainStat> TopDomains { get; set; } = new();
    public List<TrafficData> Traffic { get; set; } = new();
}

public class ConnectionInfo
{
    public string QueryName { get; set; } = "";
    public string QueryType { get; set; } = "";
    public string Status { get; set; } = "";
    public string? DnsServer { get; set; }
    public DateTime Timestamp { get; set; }
    public int Frequency { get; set; }
}

public class DomainStat
{
    public string Domain { get; set; } = "";
    public long Count { get; set; }
    public double Percentage { get; set; }
    public DateTime LastSeen { get; set; }
}

public class TrafficData 
{
    public DateTime Timestamp { get; set; }
    public int Count { get; set; }
}

public class DomainFilter
{
    public string? QueryType { get; set; }
    public string? Search { get; set; }
    public int? ProcessId { get; set; }
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }
}

public class DnsEvent
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string QueryName { get; set; } = "";
    public string QueryType { get; set; } = "";
    public string Status { get; set; } = "";
    public string? QueryResults { get; set; }
    public string? DnsServer { get; set; }
}

public class DnsEventFilter
{
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 50;
    public int? ProcessId { get; set; }
    public string? Search { get; set; } // Matches Domain or Process Name
    public string? QueryType { get; set; }
    public string? Status { get; set; }
    public string? Direction { get; set; }
    public string? StartDate { get; set; }
    public string? EndDate { get; set; }
}

public class BeaconCandidate
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public int QueryCount { get; set; }
    public double AverageIntervalSeconds { get; set; }
    public double Jitter { get; set; } // Variance percentage
}

public class PagedResult<T>
{
    public List<T> Items { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
}

public class ProcessUsage
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public long Count { get; set; }
    public DateTime LastSeen { get; set; }
}
