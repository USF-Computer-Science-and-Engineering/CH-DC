
export interface ProcessSummary {
    pid: number;
    name: string;
    totalQueries: number;
    successRate: number;
    queriesPerMinute: number;
    dataVolume: number;
    uniqueDomains: number;
}

export interface ProcessDetail {
    totalQueries: number;
    successRate: number;
    uniqueDomains: number;
}

export interface ConnectionInfo {
    queryName: string;
    queryType: string;
    status: string;
    dnsServer: string | null;
    timestamp: string;
    frequency: number;
}

export interface DomainStat {
    domain: string;
    count: number;
    percentage: number;
    lastSeen?: string;
}

export interface TrafficData {
    timestamp: string;
    count: number;
}

export interface LiveProcessData {
    connections: ConnectionInfo[];
    topDomains: DomainStat[];
    traffic: TrafficData[];
}

export interface DnsEvent {
    id: number;
    timestamp: string;
    processId: number;
    processName: string;
    queryName: string;
    queryType: string;
    status: string;
    queryResults: string | null;
    dnsServer: string | null;
}

export interface PagedResult<T> {
    items: T[];
    totalCount: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

export interface ProcessUsage {
    processId: number;
    processName: string;
    count: number;
    lastSeen: string;
}
