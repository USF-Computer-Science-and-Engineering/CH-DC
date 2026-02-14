
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using HerdWatch.Models;

namespace HerdWatch.Services;

public class DnsDataService
{
    private readonly string _dbPath;

    public DnsDataService(HerdWatchConfig config)
    {
        _dbPath = config.DbPath;
    }

    public async Task<List<ProcessSummary>> GetProcessStats()
    {
        var processes = new List<ProcessSummary>();

        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT
                    process_id,
                    process_name,
                    COUNT(*) as total_queries,
                    SUM(CASE WHEN status = 'OK' OR CAST(status AS INTEGER) = 0 THEN 1 ELSE 0 END) as successful_queries,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    COUNT(DISTINCT query_name) as unique_domains,
                    SUM(LENGTH(COALESCE(query_name, ''))) as total_query_length
                FROM dns_events
                WHERE process_id > 0
                GROUP BY process_id, process_name
                ORDER BY total_queries DESC
            ";

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                var firstSeen = DateTime.Parse(reader.GetString(4));
                var lastSeen = DateTime.Parse(reader.GetString(5));
                var duration = (lastSeen - firstSeen).TotalMinutes;
                var queriesPerMin = duration > 0 ? reader.GetInt64(2) / duration : 0;

                processes.Add(new ProcessSummary
                {
                    Pid = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    TotalQueries = reader.GetInt64(2),
                    SuccessRate = reader.GetInt64(2) > 0 ? (double)reader.GetInt64(3) / reader.GetInt64(2) * 100 : 0,
                    QueriesPerMinute = queriesPerMin,
                    DataVolume = reader.GetInt64(6),
                    UniqueDomains = reader.GetInt64(7)
                });
            }
        }
        catch { /* Ignore errors */ }

        return processes;
    }

    public async Task<ProcessDetail> GetProcessDetails(int pid)
    {
        var detail = new ProcessDetail();

        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'OK' OR CAST(status AS INTEGER) = 0 THEN 1 ELSE 0 END) as success,
                    COUNT(DISTINCT query_name) as unique_domains
                FROM dns_events
                WHERE process_id = @pid
            ";
            cmd.Parameters.AddWithValue("@pid", pid);

            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                detail.TotalQueries = reader.GetInt64(0);
                detail.SuccessRate = reader.GetInt64(0) > 0 ? (double)reader.GetInt64(1) / reader.GetInt64(0) * 100 : 0;
                detail.UniqueDomains = reader.GetInt64(2);
            }
        }
        catch { /* Ignore errors */ }

        return detail;
    }

    public async Task<LiveProcessData> GetLiveProcessData(int pid, int minutes = 10)
    {
        var data = new LiveProcessData();

        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();

            var timeFilter = minutes > 0 ? $"-{minutes} minutes" : "-10 minutes";
            var timeSql = minutes > 0 ? $"AND timestamp >= datetime('now', '{timeFilter}')" : ""; // If 0 or negative (ALL), no filter? Let's assume 0 means ALL, but for safety let's say standard usage passes valid positive int. If user wants ALL, might need different logic.
            // Actually, let's treat 0 as "All Time"
            
            cmd.CommandText = $@"
                SELECT
                    query_name,
                    query_type,
                    status,
                    dns_server,
                    timestamp,
                    COUNT(*) as frequency
                FROM dns_events
                WHERE process_id = @pid
                    {(minutes > 0 ? $"AND timestamp >= datetime('now', '-{minutes} minutes')" : "")}
                GROUP BY query_name, query_type, dns_server
                ORDER BY timestamp DESC
                LIMIT 50
            ";
            cmd.Parameters.AddWithValue("@pid", pid);

            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    data.Connections.Add(new ConnectionInfo
                    {
                        QueryName = reader.IsDBNull(0) ? "-" : reader.GetString(0),
                        QueryType = reader.IsDBNull(1) ? "-" : reader.GetString(1),
                        Status = reader.IsDBNull(2) ? "-" : reader.GetString(2),
                        DnsServer = reader.IsDBNull(3) ? null : reader.GetString(3),
                        Timestamp = reader.IsDBNull(4) ? DateTime.Now : DateTime.Parse(reader.GetString(4)),
                        Frequency = reader.GetInt32(5)
                    });
                }
            }

            cmd.CommandText = $@"
                SELECT
                    query_name as domain,
                    COUNT(*) as count,
                    COUNT(*) * 100.0 / (SELECT COUNT(*) FROM dns_events WHERE process_id = @pid {(minutes > 0 ? $"AND timestamp >= datetime('now', '-{minutes} minutes')" : "")}) as percentage
                FROM dns_events
                WHERE process_id = @pid
                    AND query_name IS NOT NULL
                    {(minutes > 0 ? $"AND timestamp >= datetime('now', '-{minutes} minutes')" : "")}
                GROUP BY query_name
                ORDER BY count DESC
                LIMIT 10
            ";

            using (var domainReader = await cmd.ExecuteReaderAsync())
            {
                while (await domainReader.ReadAsync())
                {
                    data.TopDomains.Add(new DomainStat
                    {
                        Domain = domainReader.GetString(0),
                        Count = domainReader.GetInt64(1),
                        Percentage = domainReader.GetDouble(2)
                    });
                }
            }

            // Get traffic data (bucketed by minute)
            // If viewing All Time or > 24h, maybe bucket by hour? For simplicity, stick to minute but respect filter.
            var trafficLookback = minutes > 0 ? minutes : 60; // Default to 1h if All Time to avoid massive query? Or just show last 24h?
            // Actually user wants "All Time", so we should show all. But minute buckets for all time might be too much.
            // Let's stick to the requested filter.
            
            cmd.CommandText = $@"
                SELECT 
                    strftime('%Y-%m-%d %H:%M:00', timestamp) as minute_bucket,
                    COUNT(*) as count
                FROM dns_events
                WHERE process_id = @pid
                    {(minutes > 0 ? $"AND timestamp >= datetime('now', '-{minutes} minutes')" : "")}
                GROUP BY minute_bucket
                ORDER BY minute_bucket ASC
            ";

            using (var trafficReader = await cmd.ExecuteReaderAsync())
            {
                while (await trafficReader.ReadAsync())
                {
                    if (!trafficReader.IsDBNull(0))
                    {
                        data.Traffic.Add(new TrafficData
                        {
                            Timestamp = DateTime.Parse(trafficReader.GetString(0)),
                            Count = trafficReader.GetInt32(1)
                        });
                    }
                }
            }
        }
        catch { /* Ignore errors */ }

        return data;
    }

    public async Task<List<DomainStat>> GetDomainStats(DomainFilter filter)
    {
        var domains = new List<DomainStat>();
        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            
            var sql = @"
                SELECT
                    query_name as domain,
                    COUNT(*) as count,
                    MAX(timestamp) as last_seen
                FROM dns_events
                WHERE query_name IS NOT NULL
            ";

            if (filter.ProcessId.HasValue)
            {
                sql += " AND process_id = @pid";
                cmd.Parameters.AddWithValue("@pid", filter.ProcessId.Value);
            }

            if (!string.IsNullOrEmpty(filter.QueryType) && filter.QueryType != "ALL")
            {
                sql += " AND query_type = @qtype";
                cmd.Parameters.AddWithValue("@qtype", filter.QueryType);
            }

            if (!string.IsNullOrEmpty(filter.Search))
            {
                sql += " AND query_name LIKE @search";
                cmd.Parameters.AddWithValue("@search", $"%{filter.Search}%");
            }

            if (filter.StartDate.HasValue)
            {
                sql += " AND timestamp >= @startDate";
                cmd.Parameters.AddWithValue("@startDate", filter.StartDate.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }

            if (filter.EndDate.HasValue)
            {
                sql += " AND timestamp <= @endDate";
                cmd.Parameters.AddWithValue("@endDate", filter.EndDate.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }

            sql += @"
                GROUP BY query_name
                ORDER BY count DESC
                LIMIT 100
            ";

            cmd.CommandText = sql;

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                domains.Add(new DomainStat
                {
                    Domain = reader.GetString(0),
                    Count = reader.GetInt64(1),
                    LastSeen = DateTime.Parse(reader.GetString(2))
                });
            }
        }
        catch { /* Ignore errors */ }
        return domains;
    }

    public async Task<List<string>> GetQueryTypes()
    {
        var types = new List<string>();
        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT DISTINCT query_type FROM dns_events WHERE query_type IS NOT NULL ORDER BY query_type";
            using var reader = await cmd.ExecuteReaderAsync();
            while(await reader.ReadAsync()) types.Add(reader.GetString(0));
        }
        catch {}
        return types;
    }

    public async Task<PagedResult<DnsEvent>> GetDnsEvents(DnsEventFilter filter)
    {
        var result = new PagedResult<DnsEvent>
        {
            Page = filter.Page,
            PageSize = filter.PageSize,
            Items = new List<DnsEvent>()
        };

        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();

            var whereClauses = new List<string>();
            whereClauses.Add("1=1"); // Base clause

            if (filter.ProcessId.HasValue)
            {
                whereClauses.Add("process_id = @pid");
                cmd.Parameters.AddWithValue("@pid", filter.ProcessId.Value);
            }

            if (!string.IsNullOrEmpty(filter.Search))
            {
                whereClauses.Add("(query_name LIKE @search OR process_name LIKE @search OR query_results LIKE @search)");
                cmd.Parameters.AddWithValue("@search", $"%{filter.Search}%");
            }

            if (!string.IsNullOrEmpty(filter.QueryType) && filter.QueryType != "ALL")
            {
                whereClauses.Add("query_type = @qtype");
                cmd.Parameters.AddWithValue("@qtype", filter.QueryType);
            }

            if (!string.IsNullOrEmpty(filter.Status) && filter.Status != "ALL")
            {
                whereClauses.Add("status = @status");
                cmd.Parameters.AddWithValue("@status", filter.Status);
            }

            if (!string.IsNullOrEmpty(filter.StartDate))
            {
                whereClauses.Add("timestamp >= @startDate");
                cmd.Parameters.AddWithValue("@startDate", filter.StartDate);
            }

            if (!string.IsNullOrEmpty(filter.EndDate))
            {
                whereClauses.Add("timestamp <= @endDate");
                cmd.Parameters.AddWithValue("@endDate", filter.EndDate);
            }

            if (!string.IsNullOrEmpty(filter.Direction) && filter.Direction != "ALL")
            {
                if (filter.Direction == "OUT")
                {
                    // Events representing outgoing queries
                    whereClauses.Add("event_type IN ('QUERY', 'SEND', 'WIRE_QUERY')");
                }
                else if (filter.Direction == "IN")
                {
                    // Events representing incoming responses
                    whereClauses.Add("event_type IN ('RESPONSE', 'RECV', 'NAME_ERROR')");
                }
            }

            var whereSql = string.Join(" AND ", whereClauses);

            // Count total
            cmd.CommandText = $"SELECT COUNT(*) FROM dns_events WHERE {whereSql}";
            var count = await cmd.ExecuteScalarAsync();
            result.TotalCount = Convert.ToInt32(count);

            // Get items
            cmd.CommandText = $@"
                SELECT id, timestamp, process_id, process_name, query_name, query_type, status, query_results, dns_server 
                FROM dns_events 
                WHERE {whereSql} 
                ORDER BY timestamp DESC 
                LIMIT @limit OFFSET @offset";
            
            cmd.Parameters.AddWithValue("@limit", filter.PageSize);
            cmd.Parameters.AddWithValue("@offset", (filter.Page - 1) * filter.PageSize);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                result.Items.Add(new DnsEvent
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    ProcessId = reader.GetInt32(2),
                    ProcessName = reader.IsDBNull(3) ? "?" : reader.GetString(3),
                    QueryName = reader.IsDBNull(4) ? "-" : reader.GetString(4),
                    QueryType = reader.IsDBNull(5) ? "-" : reader.GetString(5),
                    Status = reader.IsDBNull(6) ? "-" : reader.GetString(6),
                    QueryResults = reader.IsDBNull(7) ? null : reader.GetString(7),
                    DnsServer = reader.IsDBNull(8) ? null : reader.GetString(8)
                });
            }
        }
        catch {}
        return result;
    }

    public async Task ClearAllData()
    {
        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM dns_events; VACUUM;";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* Log error */ }
    }

    public async Task<List<ProcessUsage>> GetDomainProcessUsage(string domain)
    {
        var list = new List<ProcessUsage>();
        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT 
                    process_id,
                    process_name,
                    COUNT(*) as count,
                    MAX(timestamp) as last_seen
                FROM dns_events
                WHERE query_name = @domain COLLATE NOCASE
                GROUP BY process_id, process_name
                ORDER BY count DESC
            ";
            cmd.Parameters.AddWithValue("@domain", domain);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                list.Add(new ProcessUsage
                {
                    ProcessId = reader.GetInt32(0),
                    ProcessName = reader.IsDBNull(1) ? "Unknown" : reader.GetString(1),
                    Count = reader.GetInt64(2),
                    LastSeen = DateTime.Parse(reader.GetString(3))
                });
            }
        }
        catch {}
        return list;
    }

    public async Task<List<BeaconCandidate>> GetBeaconCandidates()
    {
        var candidates = new List<BeaconCandidate>();
        try
        {
            using var conn = new SqliteConnection($"Data Source={_dbPath}");
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();

            // We need timestamps to calculate jitter
            cmd.CommandText = @"
                SELECT process_id, process_name, query_name, timestamp
                FROM dns_events
                WHERE timestamp >= datetime('now', '-5 minutes')
                ORDER BY process_id, query_name, timestamp
            ";
            
            var events = new List<(int Pid, string PName, string Domain, DateTime Time)>();
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    events.Add((
                        reader.GetInt32(0),
                        reader.GetString(1),
                        reader.IsDBNull(2) ? "" : reader.GetString(2),
                        DateTime.Parse(reader.GetString(3))
                    ));
                }
            }

            var grouped = events.GroupBy(e => new { e.Pid, e.PName, e.Domain });

            foreach (var group in grouped)
            {
                if (group.Count() < 10) continue; // Need minimum samples

                var times = group.Select(x => x.Time).OrderBy(x => x).ToList();
                var intervals = new List<double>();
                for (int i = 1; i < times.Count; i++)
                {
                    intervals.Add((times[i] - times[i - 1]).TotalSeconds);
                }

                if (intervals.Count == 0) continue;

                double avgInterval = intervals.Average();
                double sumSquares = intervals.Sum(i => Math.Pow(i - avgInterval, 2));
                double stdDev = Math.Sqrt(sumSquares / intervals.Count);
                
                // Coefficient of Variation (Jitter)
                var cv = avgInterval > 0 ? stdDev / avgInterval : 0;

                // Heuristic: Low jitter (CV < 0.2) and reasonable interval (> 1s)
                // CCDC beacons are often 5s, 10s, 30s, 60s
                if (cv < 0.2 && avgInterval > 1.0)
                {
                    candidates.Add(new BeaconCandidate
                    {
                        ProcessId = group.Key.Pid,
                        ProcessName = group.Key.PName,
                        Domain = group.Key.Domain,
                        QueryCount = group.Count(),
                        AverageIntervalSeconds = Math.Round(avgInterval, 2),
                        Jitter = Math.Round(cv, 3)
                    });
                }
            }
        }
        catch { }

        return candidates;
    }
}
