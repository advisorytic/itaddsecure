import {
  Endpoint,
  Incident,
  DiscoveredHost,
  LogRecord,
  ThreatFinding,
  SeverityLevel,
  AiIndicatorItem,
  IpIntelligenceData,
  DnsAdCorrelationResult,
} from '../types/security';

// Pre-compiled fast lookup sets and dictionaries
export const SERVICE_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPCbind',
  135: 'MS RPC',
  139: 'NetBIOS',
  143: 'IMAP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  587: 'SMTP Submission',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'Microsoft SQL Server',
  1521: 'Oracle DB',
  1883: 'MQTT',
  2049: 'NFS',
  2375: 'Docker API',
  3000: 'HTTP / App',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  5985: 'WinRM HTTP',
  5986: 'WinRM HTTPS',
  6379: 'Redis',
  8000: 'HTTP / App',
  8080: 'HTTP Proxy / App',
  8443: 'HTTPS / App',
  8888: 'HTTP / App',
  9000: 'HTTP / App',
  9200: 'Elasticsearch',
  9443: 'HTTPS / App',
  27017: 'MongoDB',
};

const CRITICAL_PROCESSES = new Set(['4', 'wininit.exe', 'lsass.exe', 'services.exe', 'smss.exe', 'csrss.exe']);
const HIGH_PROCESSES = new Set(['svchost.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe']);

const SENSITIVE_PORTS = new Set([
  21, 22, 23, 25, 135, 139, 389, 445, 1433, 1521, 2375,
  3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017,
]);

const REMOTE_PORTS: Record<number, string> = {
  3389: 'RDP (Escritorio Remoto)',
  5900: 'VNC Remote Desktop',
  5901: 'VNC Display 1',
};

const PHISHING_TERMS = ['login', 'verify', 'secure', 'account', 'password', 'wallet', 'update', 'confirm', 'auth'];
const RISKY_TLDS = ['.tk', '.top', '.xyz', '.click', '.gq', '.ml', '.cf', '.men', '.work'];
const SHADOW_PORTS = new Set([21, 22, 23, 3389, 5900, 8080, 8443]);

const AI_INDICATORS = [
  'openai', 'chatgpt', 'copilot', 'gemini', 'claude', 'ollama', 'llama',
  'mistral', 'tensorflow', 'pytorch', 'cuda', 'nvidia', 'hugging face',
  'huggingface', 'jupyter', 'machine learning', 'artificial intelligence'
];

/**
 * High-performance endpoint security analysis
 */
export function analyzeEndpointSecurity(endpoint: Endpoint): ThreatFinding[] {
  const findings: ThreatFinding[] = [];
  let urlObj: URL | null = null;
  try {
    urlObj = new URL(endpoint.url);
  } catch {
    // Invalid URL format
    findings.push({
      id: `${endpoint.id}-invalid-url`,
      type: 'transport',
      severity: 'high',
      title: 'URL malformada o inválida',
      detail: `La URL '${endpoint.url}' no cumple el estándar RFC de URI.`,
      source: endpoint.name,
    });
    return findings;
  }

  const host = (urlObj.hostname || '').toLowerCase();
  const path = (urlObj.pathname || '').toLowerCase();

  // 1. Non-HTTPS warning
  if (urlObj.protocol !== 'https:') {
    findings.push({
      id: `${endpoint.id}-no-https`,
      type: 'transport',
      severity: 'high',
      title: 'Conexión sin cifrado HTTPS',
      detail: 'El endpoint transmite en texto plano vía HTTP; credenciales y datos son vulnerables a intercepción en tránsito.',
      source: endpoint.name,
    });
  }

  // 2. Phishing term heuristic
  const fullUrlStr = `${host} ${path}`;
  if (PHISHING_TERMS.some((term) => fullUrlStr.includes(term))) {
    findings.push({
      id: `${endpoint.id}-phishing-path`,
      type: 'phishing',
      severity: 'high',
      title: 'Patrón de suplantación / Phishing detectado',
      detail: 'La URL contiene palabras clave de autenticación que imitan portales legítimos.',
      source: endpoint.name,
    });
  }

  // 3. Risky TLD check
  if (RISKY_TLDS.some((tld) => host.endsWith(tld))) {
    findings.push({
      id: `${endpoint.id}-risky-tld`,
      type: 'phishing',
      severity: 'critical',
      title: 'Dominio de alto riesgo operativo (TLD abusivo)',
      detail: `El dominio utiliza una extensión de nivel superior comúnmente vinculada a infraestructuras de ataque.`,
      source: endpoint.name,
    });
  }

  // 4. Non-standard port exposure (Shadow IT)
  const portNum = urlObj.port ? parseInt(urlObj.port, 10) : (urlObj.protocol === 'https:' ? 443 : 80);
  if (SHADOW_PORTS.has(portNum)) {
    findings.push({
      id: `${endpoint.id}-shadow-port`,
      type: 'shadow-it',
      severity: 'medium',
      title: `Servicio en puerto no estándar (${portNum})`,
      detail: `Puerto ${portNum} activo; requiere validación de inventario formal y control de cambios.`,
      source: endpoint.name,
    });
  }

  // 5. Remote administration names
  if (/(vpn|jump|bastion|support|admin|remote|proxy|rdp)/i.test(host)) {
    findings.push({
      id: `${endpoint.id}-remote-admin`,
      type: 'remote-access',
      severity: 'high',
      title: 'Host de administración o acceso remoto identificado',
      detail: 'El nombre del host sugiere una pasarela de acceso remoto; verificar autorización y MFA obligatorio.',
      source: endpoint.name,
    });
  }

  return findings;
}

/**
 * Fast, pre-compiled Windows and syslog log analyzer
 */
export function analyzeLogs(records: LogRecord[]): ThreatFinding[] {
  const findings: ThreatFinding[] = [];
  const maxFindings = 150;

  for (let i = 0; i < records.length; i++) {
    if (findings.length >= maxFindings) break;
    const record = records[i];

    const rawMessage = String(record.Message || record.message || '');
    const msgLower = rawMessage.toLowerCase();
    const eventId = String(record.EventID || record.event_id || record.Id || '').trim();
    const processId = String(record.ProcessId || record.process_id || record.PID || '').trim();
    const processName = String(record.ProcessName || record.process_name || '').toLowerCase();
    const providerName = String(record.ProviderName || record.provider_name || record.source || 'Visor de Eventos');
    const user = String(record.User || record.user || '');

    const processKey = processName || processId;

    // Process criticality detection
    if (processKey) {
      if (CRITICAL_PROCESSES.has(processKey)) {
        findings.push({
          id: `finding-proc-${i}`,
          severity: 'critical',
          title: `Proceso del núcleo del sistema activo`,
          detail: `PID ${processId || 'N/A'} · ${processName || 'Proceso de sistema'} (${providerName})`,
          source: providerName,
          processId,
          processName,
          index: i,
          type: 'process',
        });
      } else if (HIGH_PROCESSES.has(processKey)) {
        findings.push({
          id: `finding-proc-${i}`,
          severity: 'high',
          title: `Intérprete o proceso de alto interés`,
          detail: `PID ${processId || 'N/A'} · ${processName || 'Intérprete de comandos'}`,
          source: providerName,
          processId,
          processName,
          index: i,
          type: 'process',
        });
      }
    }

    // Authentication failure (EventID 4625 or 4771)
    if (eventId === '4625' || eventId === '4771' || /failed login|authentication failure|inicio de sesión erróneo|bad password/i.test(msgLower)) {
      findings.push({
        id: `finding-auth-${i}`,
        severity: 'high',
        title: 'Intento de autenticación fallido (Posible fuerza bruta)',
        detail: rawMessage || `Evento ${eventId}: Fallo al autenticar usuario ${user || 'desconocido'}.`,
        source: providerName,
        processId,
        index: i,
        type: 'auth',
      });
      continue;
    }

    // New service persistence (EventID 7045 or 4697)
    if (eventId === '7045' || eventId === '4697' || /new service|servicio instalado|service created/i.test(msgLower)) {
      findings.push({
        id: `finding-svc-${i}`,
        severity: 'critical',
        title: 'Instalación de nuevo servicio en el sistema',
        detail: rawMessage || `Evento ${eventId}: Se instaló un nuevo servicio en el host (técnica T1543.003).`,
        source: providerName,
        processId,
        index: i,
        type: 'process',
      });
      continue;
    }

    // Malicious or suspicious PowerShell
    if (/powershell|encodedcommand|downloadstring|invoke-expression|-enc\s|bypass/i.test(msgLower)) {
      findings.push({
        id: `finding-ps-${i}`,
        severity: 'high',
        title: 'Actividad PowerShell potencialmente maliciosa',
        detail: rawMessage || `Ejecución de PowerShell con parámetros ofuscados o llamadas directas de descarga en memoria.`,
        source: providerName,
        processId,
        index: i,
        type: 'powershell',
      });
      continue;
    }

    // Remote access software (AnyDesk, RDP, VNC)
    if (/anydesk|mstsc\.exe|remote desktop|terminal services|vncserver|tightvnc|realvnc|teamviewer/i.test(msgLower)) {
      findings.push({
        id: `finding-remote-${i}`,
        severity: 'high',
        title: 'Software o sesión de acceso remoto detectada',
        detail: rawMessage || `Presencia de RDP, AnyDesk o VNC; requiere verificar autorización formal del personal de TI.`,
        source: providerName,
        processId,
        index: i,
        type: 'remote-access',
      });
      continue;
    }

    // Endpoint protection disabled
    if (
      /protection is disabled|participation in ksn is disabled|databases are extremely out of date|unprocessed files|antivirus disabled|defender deactivated/i.test(
        msgLower
      )
    ) {
      findings.push({
        id: `finding-def-${i}`,
        severity: 'critical',
        title: 'Protección de Endpoint / Antivirus desactivada o desactualizada',
        detail: rawMessage || 'Alerta EDR: Las firmas están obsoletas o el escudo en tiempo real fue suspendido.',
        source: providerName,
        processId,
        index: i,
        type: 'endpoint-defense',
      });
    }
  }

  return findings;
}

/**
 * Assesses network host risk and operational importance
 */
export function assessHostCriticality(host: Partial<DiscoveredHost>): {
  operationalImportance: 'critical' | 'high' | 'medium' | 'unknown';
  importanceReasons: string[];
  riskLevel: SeverityLevel;
  riskReasons: string[];
} {
  const hostName = `${host.name || ''} ${host.hostname || ''}`.toLowerCase();
  const ports = new Set((host.ports || []).map(Number));

  const roleKeywords: Record<string, string> = {
    'domain controller': 'Controlador de dominio por convención de nombre',
    'domain-controller': 'Controlador de dominio por convención de nombre',
    'dc-': 'Prefijo de equipo estándar de Active Directory Domain Controller',
    'dc0': 'Controlador de dominio AD-DS primario',
    'sql': 'Instancia de base de datos SQL corporativa',
    'database': 'Servidor de base de datos y persistencia',
    'backup': 'Servidor o repositorio de copias de seguridad',
    'firewall': 'Dispositivo perimetral o firewall de red',
    'core': 'Nodo de infraestructura core / conmutación central',
  };

  const importanceReasons: string[] = [];
  const riskReasons: string[] = [];
  let importance: 'critical' | 'high' | 'medium' | 'unknown' = 'unknown';

  for (const [kw, reason] of Object.entries(roleKeywords)) {
    if (hostName.includes(kw)) {
      importance = 'critical';
      importanceReasons.push(reason);
      break;
    }
  }

  if (importance === 'unknown') {
    if ([1433, 1521, 3306, 5432, 9200, 27017, 6379].some((p) => ports.has(p))) {
      importance = 'high';
      importanceReasons.push('Puerto de motor de base de datos o almacenamiento masivo expuesto');
    } else if ([389, 443, 8080, 8443, 9000].some((p) => ports.has(p))) {
      importance = 'medium';
      importanceReasons.push('Servicio de aplicación web o directorio LDAP activo');
    } else {
      importanceReasons.push('Rol operativo estándar o equipo terminal de usuario');
    }
  }

  // Assess exposed sensitive ports
  const exposedSensitive = Array.from(ports).filter((p) => SENSITIVE_PORTS.has(p));
  if (exposedSensitive.length > 0) {
    riskReasons.push(
      `Puertos de administración o acceso expuestos: ${exposedSensitive.map((p) => `${p} (${SERVICE_NAMES[p] || 'TCP'})`).join(', ')}`
    );
  }

  if (ports.has(23)) {
    riskReasons.push('Telnet (23) transmite sesiones en texto claro sin cifrado TLS/SSH');
  }
  if (ports.has(21)) {
    riskReasons.push('FTP (21) expone credenciales en tránsito');
  }

  let riskLevel: SeverityLevel = 'low';
  if (exposedSensitive.length >= 3 || ports.has(23)) {
    riskLevel = 'critical';
    riskReasons.push('Múltiples servicios de administración crítica expuestos simultáneamente');
  } else if (exposedSensitive.length >= 1) {
    riskLevel = 'high';
  } else if (ports.size > 0) {
    riskLevel = 'medium';
    riskReasons.push('Puertos TCP abiertos requieren validación de regla de negocio');
  }

  return {
    operationalImportance: importance,
    importanceReasons,
    riskLevel,
    riskReasons,
  };
}

/**
 * Scan network inventory for shadow AI and unauthorized LLM tools
 */
export function analyzeInventoryAi(items: Array<Record<string, unknown>>): AiIndicatorItem[] {
  const findings: AiIndicatorItem[] = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const textCorpus = [
      item.name,
      item.hostname,
      item.manufacturer,
      item.deviceType,
      item.description,
      item.software,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    const matchedIndicators = AI_INDICATORS.filter((ind) => textCorpus.includes(ind));

    if (matchedIndicators.length > 0) {
      findings.push({
        id: `ai-finding-${i}`,
        severity: matchedIndicators.includes('ollama') || matchedIndicators.includes('cuda') ? 'high' : 'medium',
        title: 'Indicador de software de Inteligencia Artificial detectado',
        detail: `El equipo ${item.ip || item.name} contiene rastros: [${matchedIndicators.join(', ')}]. La presencia no prueba exfiltración pero requiere auditar carga de proceso y acceso a datos confidenciales.`,
        ip: String(item.ip || '0.0.0.0'),
        name: String(item.name || item.hostname || 'Equipo sin nombre'),
        indicators: matchedIndicators,
      });
    }
  }

  return findings;
}

/**
 * Robust CSV parser handling different delimiters (comma, semicolon, tab, pipe)
 */
export function parseDelimitedText(content: string): Array<Record<string, string>> {
  const cleanContent = content.replace(/^\uFEFF/, '').trim();
  if (!cleanContent) return [];

  const lines = cleanContent.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];

  // Delimiter detection
  const firstLine = lines[0];
  let delimiter = ',';
  if (firstLine.includes(';') && (firstLine.match(/;/g) || []).length >= (firstLine.match(/,/g) || []).length) {
    delimiter = ';';
  } else if (firstLine.includes('\t')) {
    delimiter = '\t';
  } else if (firstLine.includes('|')) {
    delimiter = '|';
  }

  const parseLine = (lineStr: string): string[] => {
    const values: string[] = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < lineStr.length; i++) {
      const ch = lineStr[i];
      if (ch === '"') {
        if (inQuotes && lineStr[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === delimiter && !inQuotes) {
        values.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    values.push(cur.trim());
    return values;
  };

  const headers = parseLine(lines[0]).map((h) => h.toLowerCase().replace(/['"]/g, '').trim());
  const rows: Array<Record<string, string>> = [];

  for (let i = 1; i < lines.length; i++) {
    const values = parseLine(lines[i]);
    const row: Record<string, string> = {};
    headers.forEach((header, idx) => {
      row[header] = values[idx] || '';
    });
    rows.push(row);
  }

  return rows;
}

/**
 * Formats RFC compliant CSV export for incidents or endpoints
 */
export function exportToCsv(data: Array<Record<string, unknown>>, filename: string) {
  if (!data || data.length === 0) return;
  const headers = Object.keys(data[0]);
  const csvRows = [
    headers.join(','),
    ...data.map((row) =>
      headers
        .map((header) => {
          const val = row[header];
          const stringVal = val === null || val === undefined ? '' : String(val);
          return `"${stringVal.replace(/"/g, '""')}"`;
        })
        .join(',')
    ),
  ];
  const blob = new Blob([csvRows.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `${filename}-${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
