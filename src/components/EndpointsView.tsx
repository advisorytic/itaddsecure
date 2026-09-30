import React, { useState, useMemo } from 'react';
import {
  Plus,
  Upload,
  Download,
  Search,
  CheckCircle,
  AlertCircle,
  XCircle,
  Clock,
  Trash2,
  ExternalLink,
  ShieldAlert,
} from 'lucide-react';
import { Endpoint, ThreatFinding } from '../types/security';
import { analyzeEndpointSecurity, exportToCsv } from '../services/securityEngine';

interface EndpointsViewProps {
  endpoints: Endpoint[];
  onAddEndpoint: (endpoint: Omit<Endpoint, 'id' | 'createdAt'>) => void;
  onDeleteEndpoint: (id: string) => void;
  onImportCsv: (csvContent: string) => void;
  onRefreshAll: () => void;
  isChecking: boolean;
}

export const EndpointsView: React.FC<EndpointsViewProps> = ({
  endpoints,
  onAddEndpoint,
  onDeleteEndpoint,
  onImportCsv,
  onRefreshAll,
  isChecking,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'up' | 'degraded' | 'down'>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [selectedEndpointFindings, setSelectedEndpointFindings] = useState<{
    endpoint: Endpoint;
    findings: ThreatFinding[];
  } | null>(null);

  // Form states for Add Endpoint
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    ip: '',
    method: 'GET' as 'GET' | 'HEAD',
  });
  const [formError, setFormError] = useState('');

  // CSV import text
  const [csvText, setCsvText] = useState('');
  const [csvError, setCsvError] = useState('');

  // Memoized security analysis for each endpoint
  const endpointFindingsMap = useMemo(() => {
    const map = new Map<string, ThreatFinding[]>();
    endpoints.forEach((ep) => {
      map.set(ep.id, analyzeEndpointSecurity(ep));
    });
    return map;
  }, [endpoints]);

  // Filtered endpoints
  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      const matchesSearch =
        ep.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ep.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ep.ip.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === 'all' || ep.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [endpoints, searchTerm, statusFilter]);

  const handleSubmitAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      setFormError('El nombre del endpoint es obligatorio');
      return;
    }
    if (!formData.url.trim()) {
      setFormError('La URL completa es obligatoria');
      return;
    }
    try {
      const parsed = new URL(formData.url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        setFormError('La URL debe iniciar con http:// o https://');
        return;
      }
    } catch {
      setFormError('Formato de URL no válido (ejemplo: https://api.empresa.com)');
      return;
    }

    onAddEndpoint({
      name: formData.name.trim(),
      url: formData.url.trim(),
      ip: formData.ip.trim(),
      method: formData.method,
      source: 'manual',
      status: 'pending',
      httpStatus: null,
      responseTime: null,
      error: null,
      checkedAt: null,
    });

    setFormData({ name: '', url: '', ip: '', method: 'GET' });
    setFormError('');
    setShowAddModal(false);
  };

  const handleCsvImportSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!csvText.trim()) {
      setCsvError('El contenido CSV no puede estar vacío');
      return;
    }
    try {
      onImportCsv(csvText);
      setCsvText('');
      setCsvError('');
      setShowImportModal(false);
    } catch (err: unknown) {
      setCsvError(err instanceof Error ? err.message : 'Error al procesar el archivo CSV');
    }
  };

  const handleExportCsv = () => {
    const exportable = endpoints.map((ep) => ({
      ID: ep.id,
      Nombre: ep.name,
      IP: ep.ip,
      URL: ep.url,
      Metodo: ep.method,
      Estado: ep.status,
      CodigoHTTP: ep.httpStatus || '',
      Latencia_ms: ep.responseTime || '',
      Origen: ep.source,
      UltimaComprobacion: ep.checkedAt || '',
    }));
    exportToCsv(exportable, 'endpoints-monitoreados');
  };

  return (
    <div className="space-y-6">
      {/* Top action & filter bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded">
        <div className="flex flex-1 items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filtrar por nombre, IP o URL..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Interactive filter segmented control */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded">
            {(['all', 'up', 'degraded', 'down'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
                  statusFilter === st
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st === 'all'
                  ? 'Todos'
                  : st === 'up'
                  ? 'Operativo'
                  : st === 'degraded'
                  ? 'Degradado'
                  : 'Caído'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Nuevo Endpoint</span>
          </button>

          <button
            onClick={() => setShowImportModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
            title="Importar lista desde archivo CSV"
          >
            <Upload className="w-3.5 h-3.5 text-slate-400" />
            <span>Importar CSV</span>
          </button>

          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
            title="Exportar inventario a CSV"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Exportar</span>
          </button>
        </div>
      </div>

      {/* Main Endpoints Data Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-medium">
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Nombre del Activo</th>
                <th className="py-3 px-4">Dirección IP</th>
                <th className="py-3 px-4">URL del Servicio</th>
                <th className="py-3 px-4 text-center">Método</th>
                <th className="py-3 px-4 text-right">HTTP</th>
                <th className="py-3 px-4 text-right">Latencia</th>
                <th className="py-3 px-4 text-center">Alertas</th>
                <th className="py-3 px-4 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEndpoints.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    No se encontraron endpoints con los criterios seleccionados.
                  </td>
                </tr>
              ) : (
                filteredEndpoints.map((ep) => {
                  const findings = endpointFindingsMap.get(ep.id) || [];
                  const hasCritical = findings.some((f) => f.severity === 'critical');
                  const hasHigh = findings.some((f) => f.severity === 'high');

                  return (
                    <tr
                      key={ep.id}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      {/* Estado */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {ep.status === 'up' && (
                            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                          )}
                          {ep.status === 'degraded' && (
                            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                          )}
                          {ep.status === 'down' && (
                            <XCircle className="w-4 h-4 text-rose-500 shrink-0" />
                          )}
                          {ep.status === 'pending' && (
                            <Clock className="w-4 h-4 text-slate-400 shrink-0" />
                          )}
                          <span
                            className={`capitalize font-medium ${
                              ep.status === 'up'
                                ? 'text-emerald-400'
                                : ep.status === 'degraded'
                                ? 'text-amber-400'
                                : ep.status === 'down'
                                ? 'text-rose-400'
                                : 'text-slate-400'
                            }`}
                          >
                            {ep.status === 'up'
                              ? 'Operativo'
                              : ep.status === 'degraded'
                              ? 'Degradado'
                              : ep.status === 'down'
                              ? 'Caído'
                              : 'Pendiente'}
                          </span>
                        </div>
                      </td>

                      {/* Nombre */}
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-100">{ep.name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          ID: {ep.id} · Origen: {ep.source}
                        </div>
                      </td>

                      {/* IP */}
                      <td className="py-3 px-4 font-mono text-cyan-400 tabular-nums">
                        {ep.ip || '—'}
                      </td>

                      {/* URL */}
                      <td className="py-3 px-4 max-w-xs truncate">
                        <a
                          href={ep.url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="text-slate-300 hover:text-cyan-400 transition-colors inline-flex items-center gap-1 group/link truncate"
                        >
                          <span className="truncate">{ep.url}</span>
                          <ExternalLink className="w-3 h-3 shrink-0 opacity-0 group-hover/link:opacity-100 transition-opacity" />
                        </a>
                      </td>

                      {/* Método */}
                      <td className="py-3 px-4 text-center">
                        <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {ep.method}
                        </span>
                      </td>

                      {/* Código HTTP */}
                      <td className="py-3 px-4 text-right font-mono tabular-nums">
                        {ep.httpStatus ? (
                          <span
                            className={
                              ep.httpStatus >= 200 && ep.httpStatus < 300
                                ? 'text-emerald-400'
                                : ep.httpStatus >= 300 && ep.httpStatus < 400
                                ? 'text-cyan-400'
                                : 'text-rose-400'
                            }
                          >
                            {ep.httpStatus}
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>

                      {/* Latencia */}
                      <td className="py-3 px-4 text-right font-mono tabular-nums">
                        {ep.responseTime !== null && ep.responseTime !== undefined ? (
                          <span
                            className={
                              ep.responseTime < 150
                                ? 'text-emerald-400'
                                : ep.responseTime < 500
                                ? 'text-amber-400'
                                : 'text-rose-400'
                            }
                          >
                            {ep.responseTime} ms
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>

                      {/* Hallazgos de Seguridad */}
                      <td className="py-3 px-4 text-center">
                        {findings.length > 0 ? (
                          <button
                            onClick={() =>
                              setSelectedEndpointFindings({ endpoint: ep, findings })
                            }
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border transition-colors ${
                              hasCritical
                                ? 'bg-rose-950/70 border-rose-800/80 text-rose-300 hover:bg-rose-900/60'
                                : hasHigh
                                ? 'bg-amber-950/70 border-amber-800/80 text-amber-300 hover:bg-amber-900/60'
                                : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                            }`}
                          >
                            <ShieldAlert className="w-3 h-3" />
                            <span>{findings.length} aviso{findings.length > 1 ? 's' : ''}</span>
                          </button>
                        ) : (
                          <span className="text-slate-400 text-[11px]">Normal</span>
                        )}
                      </td>

                      {/* Acciones */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => onDeleteEndpoint(ep.id)}
                          className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-950/50 transition-colors"
                          title="Eliminar endpoint"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Add Endpoint */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Registrar Nuevo Endpoint
            </h3>

            {formError && (
              <div className="p-3 bg-rose-950/60 border border-rose-800/60 rounded text-rose-200 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmitAdd} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Nombre descriptivo del Activo *
                </label>
                <input
                  type="text"
                  required
                  placeholder="ej. Servidor de Pagos Core"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  URL Completa del Servicio *
                </label>
                <input
                  type="text"
                  required
                  placeholder="https://10.0.0.10:8443/health"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Dirección IP (Opcional)
                  </label>
                  <input
                    type="text"
                    placeholder="10.0.0.10"
                    value={formData.ip}
                    onChange={(e) => setFormData({ ...formData, ip: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Método HTTP
                  </label>
                  <select
                    value={formData.method}
                    onChange={(e) =>
                      setFormData({ ...formData, method: e.target.value as 'GET' | 'HEAD' })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/60 font-mono"
                  >
                    <option value="GET">GET</option>
                    <option value="HEAD">HEAD</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200 font-medium"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-slate-950 font-bold bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                >
                  Guardar Endpoint
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Import CSV */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Importar Endpoints por Lotes (CSV)
            </h3>

            <p className="text-xs text-slate-400">
              Pega el contenido CSV con encabezados <code className="text-cyan-400">name,url,ip,method</code>.
              El sniffer soporta comas, punto y coma, pipes o tabulaciones.
            </p>

            {csvError && (
              <div className="p-3 bg-rose-950/60 border border-rose-800/60 rounded text-rose-200 text-xs">
                {csvError}
              </div>
            )}

            <form onSubmit={handleCsvImportSubmit} className="space-y-4 text-xs">
              <textarea
                rows={6}
                value={csvText}
                onChange={(e) => setCsvText(e.target.value)}
                placeholder={`name,url,ip,method\nPortal Pagos,https://pay.carioca.com.do,10.0.0.12,GET\nDNS Cache,http://10.0.0.22:80,10.0.0.22,HEAD`}
                className="w-full bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500/60"
              />

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200 font-medium"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-slate-950 font-bold bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                >
                  Procesar e Importar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Findings Drawer */}
      {selectedEndpointFindings && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">
                  Evaluación de Seguridad de Endpoint
                </h3>
                <span className="text-xs text-cyan-400 font-mono">
                  {selectedEndpointFindings.endpoint.name} ({selectedEndpointFindings.endpoint.url})
                </span>
              </div>
              <button
                onClick={() => setSelectedEndpointFindings(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {selectedEndpointFindings.findings.map((finding) => (
                <div
                  key={finding.id}
                  className={`p-3 rounded border text-xs space-y-1 ${
                    finding.severity === 'critical'
                      ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
                      : finding.severity === 'high'
                      ? 'bg-amber-950/40 border-amber-800/60 text-amber-200'
                      : 'bg-slate-950 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between font-semibold">
                    <span>{finding.title}</span>
                    <span className="uppercase text-[10px] px-1.5 py-0.5 rounded font-mono border border-current">
                      {finding.severity}
                    </span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {finding.detail}
                  </p>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedEndpointFindings(null)}
                className="px-4 py-1.5 text-xs font-semibold text-slate-900 bg-slate-200 hover:bg-white rounded transition-colors"
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
