import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Header } from './components/Header';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { EndpointsView } from './components/EndpointsView';
import { ThreatHuntingView } from './components/ThreatHuntingView';
import { NetworkDiscoveryView } from './components/NetworkDiscoveryView';
import { AdDnsCorrelationView } from './components/AdDnsCorrelationView';
import { IncidentsView } from './components/IncidentsView';
import { OsintView } from './components/OsintView';
import { AiUsageDetectorView } from './components/AiUsageDetectorView';
import { SecurityModulesView } from './components/SecurityModulesView';
import { RefactorReportModal } from './components/RefactorReportModal';

import {
  Endpoint,
  Incident,
  DiscoveredHost,
  DnsAdCorrelationResult,
  IncidentStatus,
  ThreatFinding,
} from './types/security';

import {
  INITIAL_ENDPOINTS,
  INITIAL_INCIDENTS,
  INITIAL_DISCOVERED_HOSTS,
  INITIAL_CORRELATION,
  INITIAL_LOG_SAMPLES,
  INITIAL_MODULES,
} from './services/sampleData';

import {
  analyzeEndpointSecurity,
  assessHostCriticality,
  parseDelimitedText,
  SERVICE_NAMES,
} from './services/securityEngine';

export default function App() {
  // Main states with local storage caching for real persistence
  const [endpoints, setEndpoints] = useState<Endpoint[]>(() => {
    try {
      const stored = localStorage.getItem('itcar_endpoints');
      return stored ? JSON.parse(stored) : INITIAL_ENDPOINTS;
    } catch {
      return INITIAL_ENDPOINTS;
    }
  });

  const [incidents, setIncidents] = useState<Incident[]>(() => {
    try {
      const stored = localStorage.getItem('itcar_incidents');
      return stored ? JSON.parse(stored) : INITIAL_INCIDENTS;
    } catch {
      return INITIAL_INCIDENTS;
    }
  });

  const [hosts, setHosts] = useState<DiscoveredHost[]>(() => {
    try {
      const stored = localStorage.getItem('itcar_hosts');
      return stored ? JSON.parse(stored) : INITIAL_DISCOVERED_HOSTS;
    } catch {
      return INITIAL_DISCOVERED_HOSTS;
    }
  });

  const [correlation, setCorrelation] = useState<DnsAdCorrelationResult>(INITIAL_CORRELATION);
  const [activeTab, setActiveTab] = useState<ActiveTab>('endpoints');
  const [isChecking, setIsChecking] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isValidatingCorrelation, setIsValidatingCorrelation] = useState(false);
  const [showRefactorModal, setShowRefactorModal] = useState(false);

  // Sync to local storage
  useEffect(() => {
    try {
      localStorage.setItem('itcar_endpoints', JSON.stringify(endpoints));
    } catch {
      // Ignore quota error
    }
  }, [endpoints]);

  useEffect(() => {
    try {
      localStorage.setItem('itcar_incidents', JSON.stringify(incidents));
    } catch {
      // Ignore quota error
    }
  }, [incidents]);

  useEffect(() => {
    try {
      localStorage.setItem('itcar_hosts', JSON.stringify(hosts));
    } catch {
      // Ignore quota error
    }
  }, [hosts]);

  // Compute overall endpoint statistics
  const endpointStats = useMemo(() => {
    const total = endpoints.length;
    let up = 0;
    let degraded = 0;
    let down = 0;
    endpoints.forEach((ep) => {
      if (ep.status === 'up') up++;
      else if (ep.status === 'degraded') degraded++;
      else if (ep.status === 'down') down++;
    });
    return { total, up, degraded, down };
  }, [endpoints]);

  // Compute active critical findings across all endpoints
  const criticalFindingsCount = useMemo(() => {
    let count = 0;
    endpoints.forEach((ep) => {
      const findings = analyzeEndpointSecurity(ep);
      count += findings.filter((f) => f.severity === 'critical').length;
    });
    return count;
  }, [endpoints]);

  // Health check simulation (non-blocking)
  const handleCheckAll = useCallback(async () => {
    setIsChecking(true);
    await new Promise((resolve) => setTimeout(resolve, 800));

    setEndpoints((prev) =>
      prev.map((ep) => {
        // Realistic simulation based on URL & scheme
        let status = ep.status;
        let responseTime = ep.responseTime || 45;
        let httpStatus: number | null | undefined = ep.httpStatus || 200;
        let error = ep.error;

        if (ep.url.includes('.xyz') || ep.url.includes('sinkhole')) {
          status = 'down';
          httpStatus = null;
          responseTime = 8000;
          error = 'Conexión bloqueada por regla perimetral EDR';
        } else if (ep.url.startsWith('http://10.0.0.22')) {
          status = 'degraded';
          httpStatus = 403;
          responseTime = 140 + Math.floor(Math.random() * 60);
          error = 'HTTP 403 Forbidden (IIS restringido)';
        } else if (ep.url.includes('8080')) {
          status = 'degraded';
          httpStatus = 503;
          responseTime = 750 + Math.floor(Math.random() * 200);
          error = 'Servicio temporalmente saturado';
        } else {
          status = 'up';
          httpStatus = 200;
          responseTime = 30 + Math.floor(Math.random() * 45);
          error = null;
        }

        return {
          ...ep,
          status,
          httpStatus,
          responseTime,
          error,
          checkedAt: new Date().toISOString(),
        };
      })
    );
    setIsChecking(false);
  }, []);

  // Periodic monitoring cycle every 30 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      handleCheckAll();
    }, 30000);
    return () => clearInterval(timer);
  }, [handleCheckAll]);

  // Add Endpoint handler
  const handleAddEndpoint = (newEpData: Omit<Endpoint, 'id' | 'createdAt'>) => {
    const newEp: Endpoint = {
      ...newEpData,
      id: `ep-${Date.now().toString(36)}`,
      createdAt: new Date().toISOString(),
      checkedAt: new Date().toISOString(),
      status: 'up',
      httpStatus: 200,
      responseTime: 40 + Math.floor(Math.random() * 50),
    };
    setEndpoints((prev) => [newEp, ...prev]);
  };

  // Delete Endpoint handler
  const handleDeleteEndpoint = (id: string) => {
    setEndpoints((prev) => prev.filter((ep) => ep.id !== id));
  };

  // Import CSV Endpoints handler
  const handleImportCsvEndpoints = (csvContent: string) => {
    const rows = parseDelimitedText(csvContent);
    if (rows.length === 0) throw new Error('No se detectaron filas válidas en el CSV');

    const created: Endpoint[] = rows.map((row, idx) => {
      const name = row.name || row.nombre || `Endpoint ${idx + 1}`;
      const url = row.url || row.enlace || `http://${row.ip || '10.0.0.1'}`;
      const ip = row.ip || '';
      const method = (row.method || 'GET').toUpperCase() === 'HEAD' ? 'HEAD' : 'GET';

      return {
        id: `ep-csv-${Date.now().toString(36)}-${idx}`,
        name,
        url,
        ip,
        method,
        source: 'csv',
        status: 'up',
        httpStatus: 200,
        responseTime: 45 + Math.floor(Math.random() * 40),
        checkedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
    });

    setEndpoints((prev) => [...created, ...prev]);
  };

  // Create Incident handler
  const handleCreateIncident = (incData: Omit<Incident, 'id' | 'createdAt' | 'updatedAt'>) => {
    const now = new Date().toISOString();
    const newInc: Incident = {
      ...incData,
      id: `inc-${Date.now().toString(36)}`,
      createdAt: now,
      updatedAt: now,
    };
    setIncidents((prev) => [newInc, ...prev]);
  };

  // Update Incident Status handler
  const handleUpdateIncidentStatus = (id: string, status: IncidentStatus) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === id ? { ...inc, status, updatedAt: new Date().toISOString() } : inc
      )
    );
  };

  // Promote Threat Finding from Logs directly to Incident
  const handlePromoteFindingToIncident = (finding: ThreatFinding) => {
    const now = new Date().toISOString();
    const newInc: Incident = {
      id: `inc-promoted-${Date.now().toString(36)}`,
      title: finding.title,
      category:
        finding.type === 'auth'
          ? 'Acceso no autorizado'
          : finding.type === 'powershell'
          ? 'Ejecución de Código Malicioso'
          : finding.type === 'remote-access'
          ? 'Shadow IT / Acceso Remoto'
          : 'Seguridad de Host / EDR',
      description: `${finding.detail} (Detectado en registro de evento por el analizador heurístico IT-CAR-SECURE)`,
      assetName: finding.source || 'Host Interno',
      assetIp: finding.processId ? `PID: ${finding.processId}` : '10.0.0.22',
      severity: finding.severity,
      status: 'open',
      reportedBy: 'Motor Heurístico EDR',
      createdAt: now,
      updatedAt: now,
    };
    setIncidents((prev) => [newInc, ...prev]);
  };

  // Network CIDR scan simulation
  const handleRunNetworkScan = async (cidr: string, ports: number[]) => {
    setIsScanning(true);
    await new Promise((resolve) => setTimeout(resolve, 1200));

    // Simulate newly discovered host in the given subnet
    const octet = Math.floor(Math.random() * 80) + 150;
    const newIp = `10.0.0.${octet}`;
    const newHost: DiscoveredHost = {
      ip: newIp,
      hostname: `srv-auto-${octet}.carioca.corp`,
      name: `SRV-HOST-${octet}`,
      mac: `00:50:56:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(
        Math.random() * 89 + 10
      )}:${Math.floor(Math.random() * 89 + 10)}`,
      manufacturer: 'VMware Virtual Infrastructure',
      ports: [80, 443, 3389],
      services: [
        {
          port: 80,
          service: 'HTTP',
          version: 'Microsoft-IIS/10.0',
          banner: 'Microsoft-IIS/10.0',
          evidence: 'Cabecera Server publicada',
          riskLevel: 'low',
        },
        {
          port: 443,
          service: 'HTTPS',
          version: 'TLSv1.3',
          banner: 'HTTPS Service Ready',
          evidence: 'Certificado comodín corporativo válido',
          riskLevel: 'low',
        },
        {
          port: 3389,
          service: 'RDP',
          version: 'CredSSP',
          banner: 'Terminal Server NLA',
          evidence: 'Puerto 3389 abierto para gestión',
          riskLevel: 'high',
        },
      ],
      reachable: true,
      operationalImportance: 'medium',
      importanceReasons: ['Servidor de aplicación web detectado'],
      riskLevel: 'high',
      riskReasons: ['Puerto 3389 expuesto hacia la subred local'],
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'active',
      source: `Escaneo ${cidr}`,
    };

    setHosts((prev) => {
      const exists = prev.some((h) => h.ip === newHost.ip);
      return exists ? prev : [newHost, ...prev];
    });

    setIsScanning(false);
  };

  // Revalidate AD-DS / DNS Correlation
  const handleRevalidateCorrelation = async (serverIp: string) => {
    setIsValidatingCorrelation(true);
    await new Promise((resolve) => setTimeout(resolve, 900));

    const isMatch = serverIp === '10.0.0.22';
    setCorrelation({
      checkedAt: new Date().toISOString(),
      serverIp,
      dnsResponded: true,
      dnsResponseCode: 0,
      dnsError: null,
      ptrNames: isMatch ? ['dc01.carioca.com.do'] : [`host-${serverIp.replace(/\./g, '-')}.carioca.corp`],
      forwardAddresses: [serverIp],
      dnsForwardMatchesServerIp: true,
      srvRecords: isMatch
        ? [
            { type: 'SRV', value: 'dc01.carioca.com.do', priority: 0, weight: 100, port: 389 },
            { type: 'SRV', value: 'dc02.carioca.com.do', priority: 10, weight: 100, port: 389 },
          ]
        : [],
      adServerResponded: isMatch,
      adError: isMatch ? null : 'El servidor objetivo no respondió al bind LDAP en puerto 389.',
      domainName: isMatch ? 'carioca.com.do' : null,
      domainControllers: isMatch
        ? [
            { name: 'DC01-CARIOCA', hostName: 'dc01.carioca.com.do', ip: '10.0.0.22' },
            { name: 'DC02-CARIOCA', hostName: 'dc02.carioca.com.do', ip: '10.0.0.23' },
          ]
        : [],
      matchingDomainControllers: isMatch
        ? [{ name: 'DC01-CARIOCA', hostName: 'dc01.carioca.com.do', ip: '10.0.0.22' }]
        : [],
      matchingComputers: isMatch
        ? [{ name: 'DC01-CARIOCA', hostName: 'dc01.carioca.com.do', ip: '10.0.0.22' }]
        : [],
      sameServerConfirmed: isMatch,
    });
    setIsValidatingCorrelation(false);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* 3-zone Top Bar Contract */}
      <Header
        onTriggerCheck={handleCheckAll}
        isChecking={isChecking}
        onOpenRefactorModal={() => setShowRefactorModal(true)}
        endpointStats={endpointStats}
        criticalFindingsCount={criticalFindingsCount}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          incidentsCount={incidents.filter((i) => i.status !== 'resolved').length}
          threatsCount={criticalFindingsCount}
        />

        {/* Main Content Viewport */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950/90">
          <div className="max-w-7xl mx-auto space-y-6">
            {activeTab === 'endpoints' && (
              <EndpointsView
                endpoints={endpoints}
                onAddEndpoint={handleAddEndpoint}
                onDeleteEndpoint={handleDeleteEndpoint}
                onImportCsv={handleImportCsvEndpoints}
                onRefreshAll={handleCheckAll}
                isChecking={isChecking}
              />
            )}

            {activeTab === 'hunting' && (
              <ThreatHuntingView
                initialLogs={INITIAL_LOG_SAMPLES}
                onPromoteToIncident={handlePromoteFindingToIncident}
              />
            )}

            {activeTab === 'network' && (
              <NetworkDiscoveryView
                hosts={hosts}
                onAddAsEndpoint={handleAddEndpoint}
                onRunScan={handleRunNetworkScan}
                isScanning={isScanning}
              />
            )}

            {activeTab === 'ad-dns' && (
              <AdDnsCorrelationView
                correlation={correlation}
                onRevalidate={handleRevalidateCorrelation}
                isValidating={isValidatingCorrelation}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentsView
                incidents={incidents}
                onCreateIncident={handleCreateIncident}
                onUpdateStatus={handleUpdateIncidentStatus}
              />
            )}

            {activeTab === 'osint' && <OsintView />}

            {activeTab === 'shadow-ai' && <AiUsageDetectorView />}

            {activeTab === 'modules' && <SecurityModulesView modules={INITIAL_MODULES} />}
          </div>
        </main>
      </div>

      {/* Technical Refactoring Analysis Modal */}
      <RefactorReportModal
        isOpen={showRefactorModal}
        onClose={() => setShowRefactorModal(false)}
      />
    </div>
  );
}
