
import { useEffect, useState } from 'react';
import { format } from 'date-fns';
import type { PagedResult, DnsEvent } from '../types';
import { api } from '../services/api';
import { FilterBar } from './FilterBar';
import { Copyable } from './Copyable';
import { ChevronLeft, ChevronRight, Loader2 } from 'lucide-react';
import { cn } from '../lib/utils';

export function RawLogsView() {
    const [data, setData] = useState<PagedResult<DnsEvent> | null>(null);
    const [loading, setLoading] = useState(false);
    const [page, setPage] = useState(1);
    const [filters, setFilters] = useState({
        search: '',
        type: 'ALL',
        status: 'ALL'
    });

    const fetchData = async () => {
        setLoading(true);
        try {
            const res = await api.getDnsEvents(
                page,
                50,
                undefined,
                filters.search,
                filters.type,
                filters.status
            );
            setData(res);
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, [page, filters]);

    const updateFilter = (key: keyof typeof filters, value: string) => {
        setFilters(prev => ({ ...prev, [key]: value }));
        setPage(1); // Reset to first page on filter change
    };

    return (
        <div className="h-full flex flex-col space-y-4 p-6">
            <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold">Raw DNS Logs</h2>
                <div className="text-sm text-muted-foreground">
                    {data?.totalCount || 0} Events found
                </div>
            </div>

            <FilterBar
                onSearchChange={(v) => updateFilter('search', v)}
                onTypeChange={(v) => updateFilter('type', v)}
                onStatusChange={(v) => updateFilter('status', v)}
            />

            <div className="flex-1 border border-border rounded-lg overflow-hidden bg-background/50">
                <div className="h-full overflow-auto">
                    <table className="w-full text-sm text-left">
                        <thead className="text-xs text-muted-foreground uppercase bg-muted/50 sticky top-0 z-10">
                            <tr>
                                <th className="px-4 py-3">Time</th>
                                <th className="px-4 py-3">Process</th>
                                <th className="px-4 py-3">Query</th>
                                <th className="px-4 py-3">Type</th>
                                <th className="px-4 py-3">Status</th>
                                <th className="px-4 py-3">Result</th>
                                <th className="px-4 py-3">Server</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {loading && !data ? (
                                <tr>
                                    <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                                        <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                                        Loading logs...
                                    </td>
                                </tr>
                            ) : data?.items.map((event) => (
                                <tr key={event.id} className="hover:bg-muted/30">
                                    <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-muted-foreground">
                                        {format(new Date(event.timestamp), 'HH:mm:ss.SSS')}
                                    </td>
                                    <td className="px-4 py-2">
                                        <Copyable text={event.processName} className="font-medium text-foreground" />
                                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                            PID: <Copyable text={event.processId} />
                                        </div>
                                    </td>
                                    <td className="px-4 py-2 font-mono break-all">
                                        <Copyable text={event.queryName} />
                                    </td>
                                    <td className="px-4 py-2">
                                        <span className="px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 text-xs font-medium border border-blue-500/20">
                                            {event.queryType}
                                        </span>
                                    </td>
                                    <td className="px-4 py-2">
                                        <span className={cn(
                                            "px-2 py-0.5 rounded-full text-xs font-medium border",
                                            event.status === 'OK' || event.status === '0'
                                                ? "bg-green-500/10 text-green-400 border-green-500/20"
                                                : "bg-red-500/10 text-red-400 border-red-500/20"
                                        )}>
                                            {event.status === '0' ? 'OK' : event.status}
                                        </span>
                                    </td>
                                    <td className="px-4 py-2 max-w-[200px] truncate" title={event.queryResults || ''}>
                                        {event.queryResults || '-'}
                                    </td>
                                    <td className="px-4 py-2 text-muted-foreground">
                                        {event.dnsServer ? <Copyable text={event.dnsServer} /> : '-'}
                                    </td>
                                </tr>
                            ))}
                            {!loading && data?.items.length === 0 && (
                                <tr>
                                    <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                                        No logs found matching criteria
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between pt-2">
                <div className="text-sm text-muted-foreground">
                    Page {page} of {data?.totalPages || 1}
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={() => setPage(p => Math.max(1, p - 1))}
                        disabled={page === 1 || loading}
                        className="p-2 rounded-md hover:bg-muted disabled:opacity-50"
                    >
                        <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => setPage(p => Math.min(data?.totalPages || 1, p + 1))}
                        disabled={page === (data?.totalPages || 1) || loading}
                        className="p-2 rounded-md hover:bg-muted disabled:opacity-50"
                    >
                        <ChevronRight className="w-4 h-4" />
                    </button>
                </div>
            </div>
        </div>
    );
}
