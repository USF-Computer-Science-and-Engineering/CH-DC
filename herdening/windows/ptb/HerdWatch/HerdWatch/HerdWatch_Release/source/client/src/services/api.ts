
import type { ProcessSummary, ProcessDetail, LiveProcessData, DomainStat, PagedResult, DnsEvent, ProcessUsage } from '../types';

const API_BASE = import.meta.env.DEV ? 'http://localhost:5000/api' : '/api';

export const api = {
    getProcesses: async (): Promise<ProcessSummary[]> => {
        const res = await fetch(`${API_BASE}/processes`);
        if (!res.ok) throw new Error('Failed to fetch processes');
        return res.json();
    },

    getProcessDetail: async (pid: number): Promise<ProcessDetail> => {
        const res = await fetch(`${API_BASE}/process/${pid}`);
        if (!res.ok) throw new Error('Failed to fetch process details');
        return res.json();
    },

    getLiveProcessData: async (pid: number, minutes: number = 10): Promise<LiveProcessData> => {
        const res = await fetch(`${API_BASE}/process/${pid}/live?minutes=${minutes}`);
        if (!res.ok) throw new Error('Failed to fetch live data');
        return res.json();
    },

    getDomains: async (pid?: number, type?: string, search?: string): Promise<DomainStat[]> => {
        const params = new URLSearchParams();
        if (pid) params.append('pid', pid.toString());
        if (type && type !== 'ALL') params.append('type', type);
        if (search) params.append('search', search);
        const res = await fetch(`${API_BASE}/domains?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to fetch domains');
        return res.json();
    },

    getDnsEvents: async (page = 1, limit = 50, pid?: number, search?: string, type?: string, status?: string, direction?: string, start?: string, end?: string): Promise<PagedResult<DnsEvent>> => {
        const params = new URLSearchParams();
        params.append('page', page.toString());
        params.append('limit', limit.toString());
        if (pid) params.append('pid', pid.toString());
        if (search) params.append('search', search);
        if (type && type !== 'ALL') params.append('type', type);
        if (status && status !== 'ALL') params.append('status', status);
        if (direction && direction !== 'ALL') params.append('direction', direction);
        if (start) params.append('start', start);
        if (end) params.append('end', end);

        const res = await fetch(`${API_BASE}/events?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to fetch events');
        return res.json();
    },

    getTypes: async (): Promise<string[]> => {
        const res = await fetch(`${API_BASE}/types`);
        if (!res.ok) throw new Error('Failed to fetch types');
        return res.json();
    },

    getDomainUsage: async (domain: string): Promise<ProcessUsage[]> => {
        const res = await fetch(`${API_BASE}/domain-usage?domain=${encodeURIComponent(domain)}`);
        if (!res.ok) throw new Error('Failed to fetch domain usage');
        return res.json();
    },

    clearData: async (): Promise<void> => {
        const res = await fetch(`${API_BASE}/clear`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to clear data');
    },

    sinkholeDomain: async (domain: string): Promise<void> => {
        const res = await fetch(`${API_BASE}/sinkhole`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        if (!res.ok) throw new Error('Failed to sinkhole domain');
    },

    getBeaconCandidates: async (): Promise<any[]> => {
        const res = await fetch(`${API_BASE}/beacons`);
        if (!res.ok) throw new Error('Failed to fetch beacon candidates');
        return res.json();
    },

    getSinkholedDomains: async (): Promise<string[]> => {
        const res = await fetch(`${API_BASE}/sinkhole`);
        if (!res.ok) throw new Error('Failed to fetch sinkholed domains');
        return res.json();
    },

    removeSinkhole: async (domain: string): Promise<void> => {
        const res = await fetch(`${API_BASE}/sinkhole?domain=${domain}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Failed to remove sinkhole');
    }
};
