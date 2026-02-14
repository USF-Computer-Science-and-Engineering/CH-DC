
import { useState, useEffect, useRef } from 'react';
import { Activity, Shield, Search, RefreshCw, Trash2, Globe, FileText, BookOpen, AlertTriangle } from 'lucide-react';
import { api } from './services/api';
import type { ProcessSummary } from './types';
import { cn } from './lib/utils';
import { ProcessDetailView } from './components/ProcessDetailView';
import { DomainView } from './components/DomainView';
import { DomainDetailView } from './components/DomainDetailView';
import { RawLogsView } from './components/RawLogsView';
import { CheatsheetView } from './components/CheatsheetView';
import { BlackholeView } from './components/BlackholeView';
import { Toaster, type ToastMessage } from './components/Toaster';

type ViewMode = 'dashboard' | 'domains' | 'logs' | 'cheatsheet' | 'blackhole';

function App() {
  const [view, setView] = useState<ViewMode>('dashboard');
  const [processes, setProcesses] = useState<ProcessSummary[]>([]);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  // CCDC Features
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [beacons, setBeacons] = useState<Set<number>>(new Set()); // PIDs flagged as beacons
  const seenPidsRef = useRef<Set<number>>(new Set());
  const lastTxtTimeRef = useRef<string>(new Date().toISOString());

  const addToast = (title: string, description?: string, type: ToastMessage['type'] = 'info') => {
    const id = Math.random().toString(36);
    setToasts(prev => [...prev, { id, title, description, type }]);
    // Auto dismiss after 5s
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 5000);
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      if (view === 'dashboard') {
        const [procData, beaconData] = await Promise.all([
          api.getProcesses(),
          api.getBeaconCandidates()
        ]);

        // Check for new processes
        if (seenPidsRef.current.size > 0) { // Only alert after initial load
          procData.forEach(p => {
            if (!seenPidsRef.current.has(p.pid)) {
              addToast("New Process Detected", `PID ${p.pid} (${p.name}) just started making DNS queries.`, 'warning');
            }
          });
        }

        // Update seen set
        procData.forEach(p => seenPidsRef.current.add(p.pid));

        setProcesses(procData);

        // Update beacons
        const beaconPids = new Set<number>();
        beaconData.forEach((b: any) => beaconPids.add(b.processId));
        setBeacons(beaconPids);

        // Check for TXT records (CCDC Alert)
        // Poll for TXT events since last check
        const txtEvents = await api.getDnsEvents(1, 10, undefined, undefined, 'TXT', undefined, undefined, lastTxtTimeRef.current);
        if (txtEvents.items.length > 0) {
          // We have new TXT events
          // Update last check time to the most recent event + 1s (or just use current time if we assume polling covers it)
          // Better to use the latest event timestamp found.
          let maxTime = lastTxtTimeRef.current;

          txtEvents.items.forEach(evt => {
            // Verify it is actually newer (string comparison works for ISO)
            if (evt.timestamp > lastTxtTimeRef.current) {
              addToast("Suspicious TXT Record", `Process ${evt.processName} (${evt.processId}) queried TXT: ${evt.queryName}`, 'error'); // Red toast (error type usually red)
              if (evt.timestamp > maxTime) maxTime = evt.timestamp;
            }
          });

          lastTxtTimeRef.current = maxTime;
        } else {
          // Update reference time to now if nothing found, to ensure we only look forward?
          // Actually, keep it at last confirmed event or move it forward? 
          // If we find nothing, we shouldn't alert on old stuff.
          // But if we force it to Now, we might miss events between poll start and now.
          // Using the query 'start' param filters >=. 
          // Safe strategy:
          // 1. If events found, updates `lastTxtTimeRef` to latest event time.
          // 2. If no events, update `lastTxtTimeRef` to current time? No, that might skip.
          // The database timestamp is what matters. 
          // Let's just update `lastTxtTimeRef` to result.items[0].timestamp (if desc) 
          // Actually, `getDnsEvents` returns DESC order. So items[0] is the newest.
        }

        // Refine update logic:
        // Always catch up to "now" to prevent alerting on stale data if we just started, 
        // BUT we initialized with `new Date().toISOString()`, so we are good.
        // We only want *new* events.
        if (txtEvents.items.length > 0) {
          // items[0] is latest because default sort is DESC in backend
          // But wait, backend sort is ORDER BY timestamp DESC.
          const latest = txtEvents.items[0].timestamp;
          // Only update if it's new
          if (latest > lastTxtTimeRef.current) {
            lastTxtTimeRef.current = latest;
          }
        }

      }
      // Other views fetch their own data
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [view]); // Dependencies might need review if seenPids causes loop, but here it is referenced inside closure so it might be stale.
  // Actually, to avoid stale alerts, we should use functional updates or Refs.
  // Using a Ref for seenPids to allow the interval to see the latest without re-triggering the effect.




  const handleClearData = async () => {
    if (confirm('WARNING: Are you sure you want to clear ALL captured DNS data?\n\nThis action cannot be undone.')) {
      try {
        await api.clearData();
        // Refresh current view
        window.location.reload();
      } catch (e) {
        alert('Failed to clear data');
      }
    }
  };

  const filteredProcesses = processes.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.pid.toString().includes(search)
  );

  return (
    <div className="min-h-screen bg-background text-foreground font-sans flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur sticky top-0 z-10">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="bg-primary/10 p-2 rounded-lg">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-primary to-blue-600 bg-clip-text text-transparent">
                HerdWatch
              </h1>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center gap-1 bg-secondary/50 p-1 rounded-lg">
              <button
                onClick={() => setView('dashboard')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2",
                  view === 'dashboard' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                )}
              >
                <Activity className="w-4 h-4" /> Processes
              </button>
              <button
                onClick={() => setView('domains')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2",
                  view === 'domains' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                )}
              >
                <Globe className="w-4 h-4" /> Domains
              </button>
              <button
                onClick={() => setView('logs')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2",
                  view === 'logs' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                )}
              >
                <FileText className="w-4 h-4" /> Raw Logs
              </button>
              <button
                onClick={() => setView('cheatsheet')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2",
                  view === 'cheatsheet' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                )}
              >
                <BookOpen className="w-4 h-4" /> Cheatsheet
              </button>
              <button
                onClick={() => setView('blackhole')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2",
                  view === 'blackhole' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                )}
              >
                <Shield className="w-4 h-4 text-red-500" /> <span className="text-red-500">Blackhole</span>
              </button>
            </nav>
          </div>

          <div className="flex items-center gap-4">
            {view === 'dashboard' && (
              <div className="relative hidden md:block">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search processes..."
                  className="pl-9 pr-4 py-1.5 rounded-md bg-secondary/50 border-none focus:ring-1 focus:ring-primary text-sm w-64"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
              </div>
            )}

            <div className="h-6 w-px bg-border hidden md:block" />

            {/* Clear Data Button */}
            <button
              onClick={handleClearData}
              className="p-2 rounded-md hover:bg-red-500/10 text-muted-foreground hover:text-red-500 transition-colors group"
              title="Clear All Data"
            >
              <Trash2 className="w-4 h-4" />
            </button>

            <button
              onClick={fetchData}
              className="p-2 hover:bg-secondary rounded-md transition-colors"
              title="Refresh"
            >
              <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden container mx-auto px-4 py-6">
        <Toaster toasts={toasts} onDismiss={(id) => setToasts(prev => prev.filter(t => t.id !== id))} />

        {view === 'dashboard' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-[calc(100vh-120px)]">
            {/* Process List */}
            <div className="md:col-span-1 bg-card border border-border rounded-xl overflow-hidden flex flex-col shadow-sm h-full">
              <div className="p-4 border-b border-border bg-secondary/20">
                <h2 className="font-semibold flex items-center gap-2">
                  <Activity className="w-4 h-4 text-primary" />
                  Active Processes
                  <span className="ml-auto text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded-full">
                    {filteredProcesses.length}
                  </span>
                </h2>
              </div>
              <div className="flex-1 overflow-y-auto p-2 space-y-1">
                {filteredProcesses.map(proc => (
                  <button
                    key={proc.pid}
                    onClick={() => setSelectedPid(proc.pid)}
                    className={cn(
                      "w-full text-left p-3 rounded-lg cursor-pointer transition-all hover:bg-secondary/80 group",
                      selectedPid === proc.pid ? "bg-primary/10 border border-primary/20" : "border border-transparent"
                    )}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <div className="flex items-center gap-2 overflow-hidden">
                        <span className="font-medium truncate">{proc.name}</span>
                        {beacons.has(proc.pid) && (
                          <span className="shrink-0 flex items-center gap-0.5 px-1.5 py-0.5 rounded-full bg-red-500 text-white text-[10px] font-bold shadow-sm animate-pulse">
                            <AlertTriangle className="w-3 h-3" /> BEACON
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-muted-foreground font-mono">#{proc.pid}</span>
                    </div>
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span className={cn(
                        "flex items-center gap-1",
                        proc.successRate < 90 ? "text-yellow-500" : "text-green-500"
                      )}>
                        {Math.round(proc.successRate)}% success
                      </span>
                      <span>{proc.totalQueries} queries</span>
                    </div>
                    <div className="w-full bg-secondary mt-2 h-1 rounded-full overflow-hidden">
                      <div
                        className="bg-primary h-full transition-all"
                        style={{ width: `${Math.min(proc.queriesPerMinute, 100)}%` }}
                      />
                    </div>
                  </button>
                ))}

                {filteredProcesses.length === 0 && (
                  <div className="text-center py-10 text-muted-foreground text-sm">
                    No processes found
                  </div>
                )}
              </div>
            </div>

            {/* Detailed View */}
            <div className="md:col-span-2 bg-card border border-border rounded-xl overflow-hidden shadow-sm h-full">
              {selectedPid ? (
                <ProcessDetailView pid={selectedPid} onClose={() => setSelectedPid(null)} />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground p-8 text-center">
                  <div className="bg-secondary/50 p-6 rounded-full mb-4">
                    <Shield className="w-12 h-12 opacity-50" />
                  </div>
                  <h3 className="text-lg font-medium mb-2">Select a Process</h3>
                  <p className="max-w-md">
                    Click on any process from the list on the left to view detailed DNS activity.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {view === 'domains' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-[calc(100vh-120px)]">
            {/* Domain List */}
            <div className="md:col-span-1 bg-card border border-border rounded-xl overflow-hidden flex flex-col shadow-sm h-full">
              <DomainView
                onDomainClick={setSelectedDomain}
                searchTerm={search}
                selectedDomain={selectedDomain}
              />
            </div>

            {/* Domain Detail */}
            <div className="md:col-span-2 bg-card border border-border rounded-xl overflow-hidden shadow-sm h-full">
              {selectedDomain ? (
                <DomainDetailView domain={selectedDomain} onClose={() => setSelectedDomain(null)} onSinkhole={() => addToast("Domain Sinkholed", `Blocked ${selectedDomain} locally.`, "success")} />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground p-8 text-center">
                  <div className="bg-secondary/50 p-6 rounded-full mb-4">
                    <Globe className="w-12 h-12 opacity-50" />
                  </div>
                  <h3 className="text-lg font-medium mb-2">Select a Domain</h3>
                  <p className="max-w-md">
                    Click on any domain from the list to view traffic details and processes.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {view === 'logs' && (
          <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm h-[calc(100vh-120px)]">
            <RawLogsView />
          </div>
        )}

        {view === 'cheatsheet' && (
          <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm h-[calc(100vh-120px)] overflow-y-auto">
            <CheatsheetView />
          </div>
        )}

        {view === 'blackhole' && (
          <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm h-[calc(100vh-120px)]">
            <BlackholeView />
          </div>
        )}

      </main>
    </div>
  );
}

export default App;
