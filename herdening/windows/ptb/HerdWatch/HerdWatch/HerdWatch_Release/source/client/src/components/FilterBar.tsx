
import { useEffect, useState } from 'react';
import { Search, Filter, X } from 'lucide-react';
import { api } from '../services/api';
import { cn } from '../lib/utils';

interface Props {
    onSearchChange: (value: string) => void;
    onTypeChange: (value: string) => void;
    onStatusChange: (value: string) => void;
    onDirectionChange?: (value: string) => void;
    className?: string;
}

export function FilterBar({ onSearchChange, onTypeChange, onStatusChange, onDirectionChange, className }: Props) {
    const [types, setTypes] = useState<string[]>([]);
    const [searchValue, setSearchValue] = useState('');
    const [selectedType, setSelectedType] = useState('ALL');
    const [selectedStatus, setSelectedStatus] = useState('ALL');

    useEffect(() => {
        api.getTypes().then(setTypes).catch(console.error);
    }, []);

    const handleSearch = (val: string) => {
        setSearchValue(val);
        onSearchChange(val);
    };

    const statusOptions = ['ALL', 'OK', 'NoSuchName', 'Timeout', 'ServFail', 'Refused'];

    return (
        <div className={cn("flex flex-col md:flex-row gap-4 p-4 bg-muted/20 rounded-lg border border-border", className)}>
            {/* Search */}
            <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                    type="text"
                    placeholder="Search domains, IPs..."
                    value={searchValue}
                    onChange={(e) => handleSearch(e.target.value)}
                    className="w-full h-10 pl-9 pr-4 bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-ring"
                />
                {searchValue && (
                    <button
                        onClick={() => handleSearch('')}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                        <X className="w-4 h-4" />
                    </button>
                )}
            </div>

            {/* Type Filter */}
            <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-muted-foreground" />
                <select
                    value={selectedType}
                    onChange={(e) => {
                        setSelectedType(e.target.value);
                        onTypeChange(e.target.value);
                    }}
                    className="h-10 px-3 bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-ring min-w-[120px]"
                >
                    <option value="ALL">All Types</option>
                    {types.map(t => (
                        <option key={t} value={t}>{t}</option>
                    ))}
                </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-2">
                <select
                    value={selectedStatus}
                    onChange={(e) => {
                        setSelectedStatus(e.target.value);
                        onStatusChange(e.target.value);
                    }}
                    className="h-10 px-3 bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-ring min-w-[120px]"
                >
                    {statusOptions.map(s => (
                        <option key={s} value={s}>{s}</option>
                    ))}
                </select>
            </div>

            {/* Direction Filter (New) */}
            <div className="flex items-center gap-2">
                <select
                    className="h-10 px-3 bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-ring min-w-[120px]"
                    onChange={(e) => onDirectionChange && onDirectionChange(e.target.value)}
                    defaultValue="ALL"
                >
                    <option value="ALL">All Directions</option>
                    <option value="IN">Incoming</option>
                    <option value="OUT">Outgoing</option>
                </select>
            </div>
        </div>
    );
}
