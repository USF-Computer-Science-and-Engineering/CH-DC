
import { useEffect, useState } from 'react';
import { X, Activity, Server, FileText } from 'lucide-react';
import { api } from '../services/api';
import type { ProcessUsage, DnsEvent, PagedResult } from '../types';
import { format } from 'date-fns';

interface Props {
    domain: string;
    onClose: () => void;
    onSinkhole?: () => void;
}

export function DomainDetailView({ domain, onClose, onSinkhole }: Props) {
    const [usage, setUsage] = useState<ProcessUsage[]>([]);
    const [logs, setLogs] = useState<PagedResult<DnsEvent> | null>(null);
    const [page, setPage] = useState(1);
    const [filters, setFilters] = useState({
        type: 'ALL',
        status: 'ALL'
    });

    const fetchData = async () => {
        try {
            const [usageData, logsData] = await Promise.all([
                api.getDomainUsage(domain),
                api.getDnsEvents(page, 50, undefined, domain, filters.type, filters.status)
            ]);
            setUsage(usageData);
            setLogs(logsData);
        } catch (error) {
            console.error(error);
        }
    };

    useEffect(() => {
        fetchData();
    }, [domain, page, filters]);

    const totalCalls = usage.reduce((acc, curr) => acc + curr.count, 0);

    return (
        <div className="flex flex-col h-full bg-background animate-in slide-in-from-right duration-300">
            {/* Header */}
            <div className="p-4 border-b border-border flex justify-between items-center bg-secondary/20">
                <div>
                    <h2 className="text-lg font-bold flex items-center gap-2">
                        Domain Analysis
                        <span className="text-xs font-mono bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded border border-blue-500/20">{domain}</span>
                    </h2>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={async () => {
                            if (confirm(`Are you sure you want to SINKHOLE ${domain} locally?\n\nThis will add an entry to your hosts file pointing to 127.0.0.1.`)) {
                                try {
                                    await api.sinkholeDomain(domain);
                                    if (onSinkhole) onSinkhole();
                                } catch (e) {
                                    alert('Failed to sinkhole domain. Ensure the backend is running as Administrator.');
                                }
                            }
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/30 rounded text-xs font-bold transition-all"
                        title="Redirect this domain to 127.0.0.1 in hosts file"
                    >
                        <X className="w-3 h-3" /> SINKHOLE
                    </button>
                    <button onClick={onClose} className="p-1 hover:bg-secondary rounded">
                        <X className="w-5 h-5" />
                    </button>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">

                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-secondary/20 border border-border/50 p-4 rounded-xl flex flex-col items-center justify-center text-center">
                        <div className="mb-2 bg-background p-2 rounded-full shadow-sm"> <Activity className="w-5 h-5 text-purple-500" /> </div>
                        <div className="text-2xl font-bold">{totalCalls.toLocaleString()}</div>
                        <div className="text-xs text-muted-foreground uppercase tracking-wide">Total Queries</div>
                    </div>
                    <div className="bg-secondary/20 border border-border/50 p-4 rounded-xl flex flex-col items-center justify-center text-center">
                        <div className="mb-2 bg-background p-2 rounded-full shadow-sm"> <Server className="w-5 h-5 text-blue-500" /> </div>
                        <div className="text-2xl font-bold">{usage.length}</div>
                        <div className="text-xs text-muted-foreground uppercase tracking-wide">Unique Processes</div>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Top Processes */}
                    <div className="lg:col-span-1 bg-secondary/10 rounded-xl p-4 border border-border/50">
                        <h3 className="font-semibold mb-3 flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
                            Top Processes
                        </h3>
                        <div className="space-y-3">
                            {usage.map(u => (
                                <div key={u.processId} className="group">
                                    <div className="flex justify-between text-sm mb-1">
                                        <div className="flex flex-col">
                                            <span className="truncate font-medium">{u.processName}</span>
                                            <span className="text-xs text-muted-foreground">PID: {u.processId}</span>
                                        </div>
                                        <span className="text-muted-foreground">{u.count}</span>
                                    </div>
                                    <div className="w-full bg-secondary h-1.5 rounded-full overflow-hidden">
                                        <div
                                            className="bg-blue-500/80 h-full rounded-full transition-all group-hover:bg-blue-500"
                                            style={{ width: `${Math.min(100, (u.count / totalCalls) * 100)}%` }}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Logs Table */}
                    <div className="lg:col-span-2">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="font-semibold flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
                                <FileText className="w-4 h-4" /> Query Log
                            </h3>
                            {/* Mini Filter Bar */}
                            <div className="flex gap-2">
                                <select
                                    className="h-8 text-xs bg-background border border-border rounded"
                                    onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                                >
                                    <option value="ALL">All Status</option>
                                    <option value="OK">OK</option>
                                    <option value="NXDOMAIN">NXDOMAIN</option>
                                </select>
                            </div>
                        </div>

                        <div className="border border-border rounded-lg overflow-hidden bg-card">
                            <table className="w-full text-sm text-left">
                                <thead className="bg-secondary/40 text-muted-foreground uppercase text-xs">
                                    <tr>
                                        <th className="px-4 py-3">Time</th>
                                        <th className="px-4 py-3">Process</th>
                                        <th className="px-4 py-3">Type</th>
                                        <th className="px-4 py-3">Result</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {logs?.items.map((evt) => (
                                        <tr key={evt.id} className="hover:bg-secondary/20">
                                            <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                                                {format(new Date(evt.timestamp), 'HH:mm:ss')}
                                            </td>
                                            <td className="px-4 py-2">
                                                {evt.processName} <span className="text-xs text-muted-foreground">({evt.processId})</span>
                                            </td>
                                            <td className="px-4 py-2">
                                                <span className="bg-secondary px-1.5 py-0.5 rounded text-xs font-mono">{evt.queryType}</span>
                                            </td>
                                            <td className="px-4 py-2 text-xs truncate max-w-[150px]" title={evt.queryResults || ''}>
                                                {evt.queryResults || '-'}
                                            </td>
                                        </tr>
                                    ))}
                                    {logs?.items.length === 0 && (
                                        <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">No queries found</td></tr>
                                    )}
                                </tbody>
                            </table>
                        </div>

                        {/* Simple Pagination */}
                        <div className="flex justify-end gap-2 mt-2">
                            <button
                                disabled={page === 1}
                                onClick={() => setPage(p => p - 1)}
                                className="px-2 py-1 text-xs border border-border rounded disabled:opacity-50"
                            >Prev</button>
                            <span className="text-xs self-center">Page {page}</span>
                            <button
                                disabled={page === (logs?.totalPages || 1)}
                                onClick={() => setPage(p => p + 1)}
                                className="px-2 py-1 text-xs border border-border rounded disabled:opacity-50"
                            >Next</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
