export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';
export type EndpointStatus = 'up' | 'degraded' | 'down' | 'pending';
export type IncidentStatus = 'open' | 'investigating' | 'resolved';

export interface Endpoint {
  id: string;
  name: string;
  ip: string;
  url: string;
  method: 'GET' | 'HEAD';
  source: 'manual' | 'csv' | 'discovery';
  status: EndpointStatus;
  httpStatus?: number | null;
  responseTime?: number | null;
  error?: string | null;
  checkedAt?: string | null;
  createdAt: string;
}

export interface Incident {
  id: string;
  title: string;
  category: string;
  description: string;
  assetName: string;
  assetIp: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  reportedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface DiscoveredService {
  port: number;
  service: string;
  version: string;
  protocolVersion?: string;
  banner: string;
  evidence: string;
  riskLevel?: SeverityLevel;
  riskReason?: string;
}

export interface DiscoveredHost {
  ip: string;
  hostname: string | null;
  name: string;
  mac: string | null;
  manufacturer: string;
  ports: number[];
  services: DiscoveredService[];
  reachable: boolean;
  operationalImportance: 'critical' | 'high' | 'medium' | 'unknown';
  importanceReasons: string[];
  riskLevel: SeverityLevel;
  riskReasons: string[];
  firstSeen?: string;
  lastSeen?: string;
  status?: 'active' | 'inactive';
  source?: string;
}

export interface LogRecord {
  TimeCreated?: string;
  Message?: string;
  ProviderName?: string;
  EventID?: string | number;
  ProcessId?: string | number;
  ProcessName?: string;
  User?: string;
  source?: string;
  line?: number;
  [key: string]: unknown;
}

export interface ThreatFinding {
  id: string;
  severity: SeverityLevel;
  title: string;
  detail: string;
  source: string;
  processId?: string;
  processName?: string;
  index?: number;
  type?: 'transport' | 'phishing' | 'shadow-it' | 'remote-access' | 'auth' | 'process' | 'powershell' | 'endpoint-defense';
}

export interface SrvRecord {
  type: string;
  value: string;
  priority?: number;
  weight?: number;
  port?: number;
}

export interface DomainControllerInfo {
  name: string;
  hostName: string;
  ip?: string;
}

export interface DnsAdCorrelationResult {
  checkedAt: string;
  serverIp: string;
  dnsResponded: boolean;
  dnsResponseCode?: number;
  dnsError?: string | null;
  ptrNames: string[];
  forwardAddresses: string[];
  dnsForwardMatchesServerIp: boolean;
  srvRecords: SrvRecord[];
  adServerResponded: boolean;
  adError?: string | null;
  domainName: string | null;
  domainControllers: DomainControllerInfo[];
  matchingDomainControllers: DomainControllerInfo[];
  matchingComputers: DomainControllerInfo[];
  sameServerConfirmed: boolean;
}

export interface IpIntelligenceData {
  ip: string;
  public: boolean;
  message?: string | null;
  osint: {
    reverseDns?: string | null;
    name?: string | null;
    handle?: string | null;
    country?: string | null;
    startAddress?: string | null;
    endAddress?: string | null;
    entities?: string[];
    rdapError?: string | null;
  };
}

export interface AiIndicatorItem {
  id: string;
  severity: SeverityLevel;
  title: string;
  detail: string;
  ip: string;
  name: string;
  indicators: string[];
}

export interface SecurityModuleStatus {
  name: string;
  key: string;
  status: 'active' | 'configured' | 'not_configured' | 'standby';
  detail: string;
  eventCount: number;
}
