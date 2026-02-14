
import { useEffect, useState } from 'react';
import { X, Globe, Activity, BarChart } from 'lucide-react';
import { api } from '../services/api';
import type { ProcessDetail, LiveProcessData } from '../types';
import { cn } from '../lib/utils';
import { format } from 'date-fns';
import { TrafficChart } from './TrafficChart';

interface Props {
    pid: number;
    onClose: () => void;
}

export function ProcessDetailView({ pid, onClose }: Props) {
    const [details, setDetails] = useState<ProcessDetail | null>(null);
    const [liveData, setLiveData] = useState<LiveProcessData | null>(null);
    const [loading, setLoading] = useState(true);
    const [typeFilter, setTypeFilter] = useState('ALL');
    const [timeRange, setTimeRange] = useState(10); // Minutes, 0 for ALL

    const fetchData = async () => {
        try {
            const [det, live] = await Promise.all([
                api.getProcessDetail(pid),
                api.getLiveProcessData(pid, timeRange)
            ]);
            setDetails(det);
            setLiveData(live);
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        setLoading(true);
        fetchData();
        const interval = setInterval(fetchData, 2000); // 2s polling for live data
        return () => clearInterval(interval);
    }, [pid, timeRange]);

    if (loading && !details) {
        return (
            <div className="h-full flex items-center justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full">
            {/* Header */}
            <div className="p-4 border-b border-border flex justify-between items-center bg-secondary/20">
                <div>
                    <h2 className="text-lg font-bold flex items-center gap-2">
                        Process Analysis
                        <span className="text-xs font-mono bg-primary/10 text-primary px-2 py-0.5 rounded">PID: {pid}</span>
                    </h2>
                </div>

                <div className="flex items-center gap-2 ml-auto mr-4">
                    <span className="text-xs text-muted-foreground uppercase font-bold">Time Range:</span>
                    <select
                        value={timeRange}
                        onChange={(e) => setTimeRange(Number(e.target.value))}
                        className="bg-card border border-border text-xs rounded-md px-2 py-1 focus:ring-1 focus:ring-primary outline-none"
                    >
                        <option value={10}>Last 10m</option>
                        <option value={60}>Last 1h</option>
                        <option value={360}>Last 6h</option>
                        <option value={1440}>Last 24h</option>
                        <option value={0}>All Time</option>
                    </select>
                </div>

                <button onClick={onClose} className="p-1 hover:bg-secondary rounded md:hidden">
                    <X className="w-5 h-5" />
                </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">

                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <StatCard
                        icon={<Globe className="w-5 h-5 text-blue-500" />}
                        label="Unique Domains"
                        value={details?.uniqueDomains || 0}
                    />
                    <StatCard
                        icon={<Activity className="w-5 h-5 text-purple-500" />}
                        label="Total Queries"
                        value={details?.totalQueries || 0}
                    />
                    <StatCard
                        icon={<ActivityRing value={details?.successRate || 0} />}
                        label="Success Rate"
                        value={`${Math.round(details?.successRate || 0)}%`}
                    />
                </div>

                {/* Traffic Chart */}
                <div className="bg-muted/10 rounded-lg border border-border p-4">
                    <div className="flex items-center gap-2 mb-4">
                        <BarChart className="w-4 h-4 text-blue-400" />
                        <h3 className="text-sm font-semibold uppercase tracking-wide">Traffic Volume</h3>
                    </div>
                    <TrafficChart data={liveData?.traffic || []} />
                </div>

                {/* Top Domains & Live Feed Split */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Top Domains */}
                    <div className="lg:col-span-1 bg-secondary/10 rounded-xl p-4 border border-border/50">
                        <h3 className="font-semibold mb-3 flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
                            Top Domains
                        </h3>
                        <div className="space-y-3">
                            {liveData?.topDomains.map(d => (
                                <div key={d.domain} className="group">
                                    <div className="flex justify-between text-sm mb-1 items-center">
                                        <div className="flex items-center gap-2 truncate">
                                            <span className="truncate font-medium" title={d.domain}>{d.domain}</span>
                                            <button
                                                onClick={async (e) => {
                                                    e.stopPropagation();
                                                    if (confirm(`Sinkhole ${d.domain}?`)) {
                                                        try {
                                                            await api.sinkholeDomain(d.domain);
                                                        } catch (err) {
                                                            alert('Failed to sinkhole');
                                                        }
                                                    }
                                                }}
                                                className="opacity-0 group-hover:opacity-100 p-0.5 hover:bg-red-500/20 text-red-500 rounded transition-all"
                                                title="Sinkhole Domain"
                                            >
                                                <X className="w-3 h-3" />
                                            </button>
                                        </div>
                                        <span className="text-muted-foreground">{d.count}</span>
                                    </div>
                                    <div className="w-full bg-secondary h-1.5 rounded-full overflow-hidden">
                                        <div
                                            className="bg-primary/80 h-full rounded-full transition-all group-hover:bg-primary"
                                            style={{ width: `${d.percentage}%` }}
                                        />
                                    </div>
                                </div>
                            ))}
                            {liveData?.topDomains.length === 0 && (
                                <div className="text-muted-foreground text-sm italic">No data yet</div>
                            )}
                        </div>
                    </div>

                    {/* Live Feed Table */}
                    <div className="lg:col-span-2">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="font-semibold flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
                                Recent Activity
                            </h3>
                            <select
                                value={typeFilter}
                                onChange={(e) => setTypeFilter(e.target.value)}
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
                        <div className="border border-border rounded-lg overflow-hidden bg-card">
                            <table className="w-full text-sm text-left">
                                <thead className="bg-secondary/40 text-muted-foreground uppercase text-xs">
                                    <tr>
                                        <th className="px-4 py-3">Time</th>
                                        <th className="px-4 py-3">Query</th>
                                        <th className="px-4 py-3">Type</th>
                                        <th className="px-4 py-3">Status</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {liveData?.connections
                                        .filter(c => typeFilter === 'ALL' || c.queryType === typeFilter)
                                        .map((conn, i) => (
                                            <tr key={i} className="hover:bg-secondary/20 transition-colors">
                                                <td className="px-4 py-2 text-muted-foreground font-mono text-xs whitespace-nowrap">
                                                    {format(new Date(conn.timestamp), 'HH:mm:ss')}
                                                </td>
                                                <td className="px-4 py-2 font-medium max-w-[200px] truncate" title={conn.queryName}>
                                                    {conn.queryName}
                                                </td>
                                                <td className="px-4 py-2">
                                                    <span className="bg-secondary px-1.5 py-0.5 rounded text-xs text-secondary-foreground font-mono">
                                                        {conn.queryType}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-2">
                                                    <StatusBadge status={conn.status} />
                                                </td>
                                            </tr>
                                        ))}
                                    {liveData?.connections.length === 0 && (
                                        <tr>
                                            <td colSpan={4} className="p-8 text-center text-muted-foreground">
                                                No recent DNS activity
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode, label: string, value: string | number }) {
    return (
        <div className="bg-secondary/20 border border-border/50 p-4 rounded-xl flex flex-col items-center justify-center text-center hover:bg-secondary/30 transition-colors">
            <div className="mb-2 bg-background p-2 rounded-full shadow-sm">{icon}</div>
            <div className="text-2xl font-bold">{value}</div>
            <div className="text-xs text-muted-foreground uppercase tracking-wide">{label}</div>
        </div>
    );
}

function StatusBadge({ status }: { status: string }) {
    const isErr = status !== 'OK' && status !== '0';
    return (
        <span className={cn(
            "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium",
            isErr ? "bg-red-500/10 text-red-500 border border-red-500/20" : "bg-green-500/10 text-green-500 border border-green-500/20"
        )}>
            {isErr && <img src="/icons/alert.svg" className="w-3 h-3" />}
            {status}
        </span>
    );
}

function ActivityRing({ value }: { value: number }) {
    const radius = 10;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (value / 100) * circumference;

    return (
        <div className="relative w-5 h-5">
            <svg className="w-full h-full -rotate-90">
                <circle cx="10" cy="10" r={radius} fill="transparent" stroke="currentColor" strokeWidth="3" className="text-muted-foreground/20" />
                <circle
                    cx="10"
                    cy="10"
                    r={radius}
                    fill="transparent"
                    stroke={value > 90 ? "rgb(34, 197, 94)" : "rgb(239, 68, 68)"}
                    strokeWidth="3"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                />
            </svg>
        </div>
    );
}
