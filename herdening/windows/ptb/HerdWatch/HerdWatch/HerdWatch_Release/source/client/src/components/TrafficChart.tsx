
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { TrafficData } from '../types';
import { format } from 'date-fns';

interface Props {
    data: TrafficData[];
}

export function TrafficChart({ data }: Props) {
    if (!data || data.length === 0) {
        return (
            <div className="h-[200px] flex items-center justify-center text-muted-foreground border border-dashed rounded-lg bg-black/20">
                No traffic data available
            </div>
        );
    }

    return (
        <div className="h-[200px] w-full bg-black/20 p-2 rounded-lg border border-white/5">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data}>
                    <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                    <XAxis
                        dataKey="timestamp"
                        tickFormatter={(str) => format(new Date(str), 'HH:mm')}
                        stroke="#94a3b8"
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                        minTickGap={30}
                    />
                    <YAxis
                        stroke="#94a3b8"
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                        width={30}
                    />
                    <Tooltip
                        cursor={{ stroke: '#22c55e', strokeWidth: 1, strokeDasharray: '4 4' }}
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontSize: '12px' }}
                        itemStyle={{ color: '#22c55e' }}
                        labelFormatter={(label) => format(new Date(label), 'HH:mm:ss')}
                    />
                    <Area
                        type="step"
                        dataKey="count"
                        stroke="#22c55e"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#colorCount)"
                        name="Queries"
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
