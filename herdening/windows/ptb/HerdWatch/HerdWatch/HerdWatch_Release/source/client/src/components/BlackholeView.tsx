import { useEffect, useState } from 'react';
import { ShieldAlert, Trash2, Globe, RefreshCcw } from 'lucide-react';
import { api } from '../services/api';

export function BlackholeView() {
    const [domains, setDomains] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);

    const fetchData = async () => {
        setLoading(true);
        try {
            const data = await api.getSinkholedDomains();
            setDomains(data);
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleRevert = async (domain: string) => {
        if (!confirm(`Are you sure you want to remove ${domain} from the sinkhole (hosts file)?`)) return;

        try {
            await api.removeSinkhole(domain);
            await fetchData();
        } catch (e) {
            alert('Failed to remove sinkhole. Ensure backend is running as Admin.');
        }
    };

    return (
        <div className="flex flex-col h-full bg-background animate-in fade-in duration-300">
            <div className="p-4 border-b border-border bg-red-500/10 flex items-center justify-between">
                <h2 className="font-semibold flex items-center gap-2 text-red-500">
                    <ShieldAlert className="w-5 h-5" />
                    Blackholed Domains
                    <span className="text-xs text-background bg-red-500 px-2 py-0.5 rounded-full">
                        {domains.length}
                    </span>
                </h2>
                <button
                    onClick={fetchData}
                    className="p-1.5 hover:bg-red-500/10 rounded-md text-red-500 transition-colors"
                >
                    <RefreshCcw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4">
                {domains.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-muted-foreground opacity-50">
                        <ShieldAlert className="w-16 h-16 mb-4" />
                        <p>No domains currently sinkholed in hosts file.</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {domains.map(domain => (
                            <div key={domain} className="bg-card border border-border p-3 rounded-lg flex items-center justify-between group hover:border-red-500/30 transition-all">
                                <div className="flex items-center gap-3">
                                    <div className="bg-red-500/10 p-2 rounded-md text-red-500">
                                        <Globe className="w-4 h-4" />
                                    </div>
                                    <span className="font-mono text-sm">{domain}</span>
                                </div>
                                <button
                                    onClick={() => handleRevert(domain)}
                                    className="p-2 text-muted-foreground hover:text-green-500 hover:bg-green-500/10 rounded-md transition-all opacity-100 md:opacity-0 group-hover:opacity-100"
                                    title="Revert (Unblock)"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
