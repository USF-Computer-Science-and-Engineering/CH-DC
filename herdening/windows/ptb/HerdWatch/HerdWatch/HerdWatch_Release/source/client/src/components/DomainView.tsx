
import { useEffect, useState } from 'react';
import type { DomainStat } from '../types';
import { api } from '../services/api';

import { format } from 'date-fns';
import { Loader2, Globe } from 'lucide-react';

import { cn } from '../lib/utils';

interface Props {
    onDomainClick: (domain: string) => void;
    searchTerm: string;
    selectedDomain: string | null;
}

export function DomainView({ onDomainClick, searchTerm, selectedDomain }: Props) {
    const [data, setData] = useState<DomainStat[]>([]);
    const [loading, setLoading] = useState(false);
    const [selectedType, setSelectedType] = useState('ALL');
    const [timeRange, setTimeRange] = useState('ALL'); // '10m', '1h', '24h', 'ALL'

    const fetchData = async () => {
        setLoading(true);
        try {
            // Calculate start date if not ALL
            // api.getDomains signature is (pid?: number, type: string = 'ALL', search: string = '')
            // Wait, getDomains in api.ts doesn't support startDate yet?
            // Checking api.ts... it calls /api/domains?pid=...&type=...&search=...
            // It doesn't seem to expose start/end date args in the current api.ts function signature I see in context?
            // Let's assume I might need to update api.ts for getDomains to accept more args or I just modify getDomains to take an object.
            // Currently: getDomains: async (pid?: number, type: string = 'ALL', search: string = ''): Promise<DomainStat[]>
            // I should update api.ts first to support this properly or at least pass query params.
            // But for now, I'll pass it if I can or hack it?
            // The backend /api/domains DOES take pid, type, search. It DOES NOT take start/end date in the mapped endpoint in Program.cs?
            // Let me check Program.cs again.
            // Program.cs: app.MapGet("/api/domains", async (int? pid, string? type, string? search, DnsDataService dataService)
            // It DOES NOT take start/end.
            // I need to update Program.cs and DnsDataService.cs (GetDomainStats) to support time filtering too!
            // GetDomainStats takes DomainFilter which DOES NOT have StartDate currently?
            // Checking DnsDataService.cs GetDomainStats... it takes DomainFilter.
            // DomainFilter definition? It is in Models.cs. I haven't seen Models.cs content fully but based on usage in DnsDataService.cs:
            // if (filter.ProcessId.HasValue) ... if (filter.QueryType) ... if (filter.Search) ...
            // It does NOT seem to have date filtering implemented in GetDomainStats SQL.
            // I need to add timestamp filtering to GetDomainStats first.

            // Re-reading my plan... "Update GetDomainStats call in API to calculate StartDate based on selected range."
            // So I definitely need to add that support.

            // Since I cannot update the API call in this tool step without fixing the backend first, I will use a placeholder or 
            // comment out the time filter part in fetchData for now until backend supports it.
            // accessing api.getDomains
            const res = await api.getDomains(undefined, selectedType, searchTerm);
            // TODO: Pass time filter once backend updated
            setData(res);
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const timeout = setTimeout(fetchData, 300); // Debounce search
        return () => clearTimeout(timeout);
    }, [searchTerm, selectedType, timeRange]);

    return (
        <div className="h-full flex flex-col flex-1">
            <div className="p-4 border-b border-border bg-secondary/20 flex items-center justify-between">
                <h2 className="font-semibold flex items-center gap-2">
                    <Globe className="w-4 h-4 text-primary" />
                    Top Domains
                    <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded-full">
                        {data.length}
                    </span>
                </h2>
                <div className="flex gap-2">
                    <select
                        value={timeRange}
                        onChange={(e) => setTimeRange(e.target.value)}
                        className="bg-card border border-border text-xs rounded-md px-2 py-1 focus:ring-1 focus:ring-primary outline-none"
                    >
                        <option value="10">Last 10m</option>
                        <option value="60">Last 1h</option>
                        <option value="360">Last 6h</option>
                        <option value="1440">Last 24h</option>
                        <option value="ALL">All Time</option>
                    </select>
                    <select
                        value={selectedType}
                        onChange={(e) => setSelectedType(e.target.value)}
                        className="bg-card border border-border text-xs rounded-md px-2 py-1 focus:ring-1 focus:ring-primary outline-none"
                    >
                        <option value="ALL">All Types</option>
                        <option value="A">A</option>
                        <option value="AAAA">AAAA</option>
                        <option value="CNAME">CNAME</option>
                        <option value="TXT">TXT</option>
                        <option value="SRV">SRV</option>
                        <option value="PTR">PTR</option>
                        <option value="MX">MX</option>
                        <option value="HTTPS">HTTPS</option>
                    </select>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto p-2 space-y-1">
                {loading ? (
                    <div className="flex justify-center py-8">
                        <Loader2 className="w-6 h-6 animate-spin text-primary" />
                    </div>
                ) : data.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground text-sm">
                        No domains found
                    </div>
                ) : (
                    data.map((domain, i) => (
                        <button
                            key={i}
                            onClick={() => onDomainClick(domain.domain)}
                            className={cn(
                                "w-full text-left p-3 rounded-lg cursor-pointer transition-all hover:bg-secondary/80 group",
                                selectedDomain === domain.domain ? "bg-primary/10 border border-primary/20" : "border border-transparent"
                            )}
                        >
                            <div className="flex items-center justify-between mb-1">
                                <span className="font-medium truncate text-sm" title={domain.domain}>{domain.domain}</span>
                                <span className="text-xs text-muted-foreground font-mono">
                                    {domain.lastSeen ? format(new Date(domain.lastSeen), 'HH:mm') : '-'}
                                </span>
                            </div>
                            <div className="flex justify-between text-xs text-muted-foreground">
                                <span>{domain.count.toLocaleString()} queries</span>
                            </div>
                            {/* Simple visual bar */}
                            <div className="w-full bg-secondary mt-1.5 h-1 rounded-full overflow-hidden">
                                <div
                                    className="bg-blue-500 h-full transition-all"
                                    style={{ width: `${Math.min(100, Math.max(5, (domain.count / (data[0]?.count || 1)) * 100))}%` }}
                                />
                            </div>
                        </button>
                    ))
                )}
            </div>
        </div>
    );
}
