import React, { useState, useMemo } from 'react';
import {
  Search,
  Upload,
  FileText,
  AlertTriangle,
  Flame,
  Terminal,
  ShieldOff,
  UserX,
  PlusCircle,
  CheckCircle,
} from 'lucide-react';
import { LogRecord, ThreatFinding, SeverityLevel } from '../types/security';
import { analyzeLogs, parseDelimitedText } from '../services/securityEngine';

interface ThreatHuntingViewProps {
  initialLogs: LogRecord[];
  onPromoteToIncident: (finding: ThreatFinding) => void;
}

export const ThreatHuntingView: React.FC<ThreatHuntingViewProps> = ({
  initialLogs,
  onPromoteToIncident,
}) => {
  const [logs, setLogs] = useState<LogRecord[]>(initialLogs);
  const [severityFilter, setSeverityFilter] = useState<'all' | SeverityLevel>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [promotedIds, setPromotedIds] = useState<Set<string>>(new Set());
  const [showUploadBox, setShowUploadBox] = useState(false);
  const [rawTextLog, setRawTextLog] = useState('');
  const [uploadError, setUploadError] = useState('');

  // Memoized threat analysis
  const findings = useMemo(() => {
    return analyzeLogs(logs);
  }, [logs]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
      const matchesSearch =
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.detail.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (f.processName && f.processName.toLowerCase().includes(searchTerm.toLowerCase()));
      return matchesSeverity && matchesSearch;
    });
  }, [findings, severityFilter, searchTerm]);

  const handlePromote = (finding: ThreatFinding) => {
    onPromoteToIncident(finding);
    setPromotedIds((prev) => new Set(prev).add(finding.id));
  };

  const handleProcessLogText = (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawTextLog.trim()) {
      setUploadError('Por favor ingresa o pega contenido de log');
      return;
    }

    try {
      // Check if it's JSON array
      if (rawTextLog.trim().startsWith('[') || rawTextLog.trim().startsWith('{')) {
        const parsed = JSON.parse(rawTextLog);
        const list = Array.isArray(parsed) ? parsed : [parsed];
        setLogs(list);
      } else if (rawTextLog.includes(',') || rawTextLog.includes(';') || rawTextLog.includes('\t')) {
        // Delimited CSV
        const parsedRows = parseDelimitedText(rawTextLog);
        if (parsedRows.length === 0) throw new Error('No se detectaron registros estructurados');
        setLogs(parsedRows);
      } else {
        // Plaintext line-by-line
        const lines = rawTextLog.split(/\r?\n/).filter((l) => l.trim().length > 0);
        const records: LogRecord[] = lines.map((line, idx) => ({
          Message: line,
          ProviderName: 'Archivo de texto',
          line: idx + 1,
        }));
        setLogs(records);
      }
      setShowUploadBox(false);
      setRawTextLog('');
      setUploadError('');
    } catch (err: unknown) {
      setUploadError(err instanceof Error ? err.message : 'Error al parsear el archivo de log');
    }
  };

  const handleResetSampleLogs = () => {
    setLogs(initialLogs);
  };

  return (
    <div className="space-y-6">
      {/* Top summary & trigger panel */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Flame className="w-4 h-4 text-cyan-400" />
            Caza de Amenazas en Logs (Eventos Windows & Syslog)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Motor de correlación heurística para detección de TTPs (Técnicas, Tácticas y Procedimientos)
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowUploadBox(!showUploadBox)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
          >
            <Upload className="w-3.5 h-3.5 text-slate-400" />
            <span>Cargar / Pegar Logs</span>
          </button>

          <button
            onClick={handleResetSampleLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors whitespace-nowrap"
          >
            Restaurar Muestra
          </button>
        </div>
      </div>

      {/* Upload Drawer if opened */}
      {showUploadBox && (
        <div className="bg-slate-900 border border-cyan-500/30 rounded p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-cyan-300">
              Carga directa de registros (CSV exportado del Visor de Eventos, JSON o Syslog)
            </span>
            <button
              onClick={() => setShowUploadBox(false)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              ✕
            </button>
          </div>

          {uploadError && (
            <div className="p-2 bg-rose-950/60 border border-rose-800 rounded text-rose-200 text-xs">
              {uploadError}
            </div>
          )}

          <form onSubmit={handleProcessLogText} className="space-y-3">
            <textarea
              rows={4}
              value={rawTextLog}
              onChange={(e) => setRawTextLog(e.target.value)}
              placeholder="Pega aquí los eventos de Windows en formato JSON, CSV o texto plano..."
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
            />
            <div className="flex justify-end gap-2">
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
              >
                Analizar Registros
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filter and stats row */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 p-3 border border-slate-800 rounded text-xs">
        <div className="flex flex-1 items-center gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Buscar por proceso, PID o texto..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded font-medium transition-colors ${
                  severityFilter === sev
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev === 'all'
                  ? 'Todas'
                  : sev === 'critical'
                  ? 'Críticas'
                  : sev === 'high'
                  ? 'Altas'
                  : sev === 'medium'
                  ? 'Medias'
                  : 'Bajas'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3 text-slate-400 font-mono text-[11px]">
          <span>Eventos analizados: <strong className="text-slate-200 tabular-nums">{logs.length}</strong></span>
          <span aria-hidden="true">·</span>
          <span>Detecciones activas: <strong className="text-amber-400 tabular-nums">{findings.length}</strong></span>
        </div>
      </div>

      {/* Threat findings cards / table */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded text-slate-400 text-xs">
            No se detectaron anomalías con los filtros actuales.
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isPromoted = promotedIds.has(finding.id);

            return (
              <div
                key={finding.id}
                className={`p-4 rounded border transition-colors bg-slate-900 ${
                  finding.severity === 'critical'
                    ? 'border-rose-900/60 hover:border-rose-700/80'
                    : finding.severity === 'high'
                    ? 'border-amber-900/60 hover:border-amber-700/80'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <div
                      className={`w-7 h-7 rounded flex items-center justify-center shrink-0 mt-0.5 ${
                        finding.severity === 'critical'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800/80'
                          : finding.severity === 'high'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800/80'
                          : 'bg-slate-800 text-cyan-400 border border-slate-700'
                      }`}
                    >
                      {finding.type === 'auth' ? (
                        <UserX className="w-3.5 h-3.5" />
                      ) : finding.type === 'powershell' ? (
                        <Terminal className="w-3.5 h-3.5" />
                      ) : finding.type === 'endpoint-defense' ? (
                        <ShieldOff className="w-3.5 h-3.5" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      )}
                    </div>

                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-100">
                          {finding.title}
                        </span>
                        <span
                          className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                            finding.severity === 'critical'
                              ? 'text-rose-400 border-rose-800/60 bg-rose-950/50'
                              : finding.severity === 'high'
                              ? 'text-amber-400 border-amber-800/60 bg-amber-950/50'
                              : 'text-slate-400 border-slate-700 bg-slate-800'
                          }`}
                        >
                          {finding.severity}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed font-mono text-[11px]">
                        {finding.detail}
                      </p>

                      <div className="flex items-center gap-3 text-[11px] text-slate-400 pt-1 font-mono">
                        <span>Origen: {finding.source}</span>
                        {finding.processId && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span>PID: {finding.processId}</span>
                          </>
                        )}
                        {finding.processName && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span>Proceso: {finding.processName}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="shrink-0 flex sm:flex-col items-center sm:items-end justify-between sm:justify-start gap-2 pt-2 sm:pt-0">
                    <button
                      onClick={() => handlePromote(finding)}
                      disabled={isPromoted}
                      className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                        isPromoted
                          ? 'bg-slate-800 text-emerald-400 border border-emerald-800/40 cursor-default'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                      }`}
                    >
                      {isPromoted ? (
                        <>
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Promovido a Incidencia</span>
                        </>
                      ) : (
                        <>
                          <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Promover a Incidencia</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
