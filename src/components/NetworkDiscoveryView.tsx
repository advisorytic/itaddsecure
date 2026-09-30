import React, { useState } from 'react';
import {
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  Plus,
  Radio,
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { DiscoveredHost, Endpoint } from '../types/security';
import { SERVICE_NAMES } from '../services/securityEngine';

interface NetworkDiscoveryViewProps {
  hosts: DiscoveredHost[];
  onAddAsEndpoint: (endpoint: Omit<Endpoint, 'id' | 'createdAt'>) => void;
  onRunScan: (cidr: string, ports: number[]) => void;
  isScanning: boolean;
}

export const NetworkDiscoveryView: React.FC<NetworkDiscoveryViewProps> = ({
  hosts,
  onAddAsEndpoint,
  onRunScan,
  isScanning,
}) => {
  const [cidr, setCidr] = useState('10.0.0.0/24');
  const [selectedPortProfile, setSelectedPortProfile] = useState<'standard' | 'extended'>('standard');
  const [expandedHostIp, setExpandedHostIp] = useState<string | null>(null);

  const handleScanTrigger = (e: React.FormEvent) => {
    e.preventDefault();
    const ports =
      selectedPortProfile === 'standard'
        ? [21, 22, 53, 80, 135, 139, 389, 443, 445, 1433, 3389, 8080]
        : [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 389, 443, 445, 1433,
            1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443,
          ];
    onRunScan(cidr, ports);
  };

  const handleQuickAdd = (host: DiscoveredHost, port: number) => {
    const isTls = [443, 8443, 9443].includes(port);
    const protocol = isTls ? 'https' : 'http';
    const defaultUrl = `${protocol}://${host.ip}:${port}`;

    onAddAsEndpoint({
      name: `${host.name} (${SERVICE_NAMES[port] || 'Port ' + port})`,
      url: defaultUrl,
      ip: host.ip,
      method: 'GET',
      source: 'discovery',
      status: 'pending',
      httpStatus: null,
      responseTime: null,
      error: null,
      checkedAt: null,
    });
  };

  return (
    <div className="space-y-6">
      {/* Top scan controls */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4">
        <form onSubmit={handleScanTrigger} className="flex flex-col md:flex-row items-stretch md:items-end justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Descubrimiento Pasivo y Activo de Red CIDR
            </h2>
            <p className="text-xs text-slate-400">
              Sondeo no intrusivo de puertos TCP, extracción de banners y clasificación de activos
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">
                Subred IPv4 (CIDR)
              </label>
              <input
                type="text"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="10.0.0.0/24"
                className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-cyan-400 font-mono focus:outline-none focus:border-cyan-500/60"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">
                Perfil de Puertos
              </label>
              <select
                value={selectedPortProfile}
                onChange={(e) =>
                  setSelectedPortProfile(e.target.value as 'standard' | 'extended')
                }
                className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
              >
                <option value="standard">Comunes (12 puertos estándar)</option>
                <option value="extended">Extendido (25 puertos de infraestructura)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="flex items-center gap-2 px-4 py-1.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-60 whitespace-nowrap mt-4 md:mt-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Escaneando Subred...' : 'Iniciar Escaneo'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Discovered Hosts List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span>Equipos detectados en inventario: <strong className="text-slate-200 tabular-nums">{hosts.length}</strong></span>
          <span>Actualización en tiempo real</span>
        </div>

        {hosts.map((host) => {
          const isExpanded = expandedHostIp === host.ip;

          return (
            <div
              key={host.ip}
              className={`bg-slate-900 border rounded transition-all ${
                host.riskLevel === 'critical'
                  ? 'border-rose-900/60'
                  : host.riskLevel === 'high'
                  ? 'border-amber-900/60'
                  : 'border-slate-800'
              }`}
            >
              {/* Host Header Card */}
              <div
                onClick={() => setExpandedHostIp(isExpanded ? null : host.ip)}
                className="p-4 cursor-pointer hover:bg-slate-850/50 flex flex-col md:flex-row md:items-center justify-between gap-4 select-none"
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`w-9 h-9 rounded flex items-center justify-center shrink-0 ${
                      host.operationalImportance === 'critical'
                        ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    <Server className="w-4 h-4" />
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-100">
                        {host.name}
                      </span>
                      <span className="text-xs font-mono text-cyan-400 tabular-nums">
                        {host.ip}
                      </span>
                      {host.hostname && host.hostname !== host.name && (
                        <span className="text-[11px] text-slate-400 font-mono">
                          ({host.hostname})
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                      <span>Fabricante: {host.manufacturer || 'No identificado'}</span>
                      <span aria-hidden="true">·</span>
                      <span>MAC: {host.mac || 'No disponible'}</span>
                      <span aria-hidden="true">·</span>
                      <span>Origen: {host.source || 'Escaneo directo'}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right space-y-0.5">
                    <div className="flex items-center gap-1.5 justify-end">
                      <span
                        className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                          host.riskLevel === 'critical'
                            ? 'text-rose-400 border-rose-800/80 bg-rose-950/60'
                            : host.riskLevel === 'high'
                            ? 'text-amber-400 border-amber-800/80 bg-amber-950/60'
                            : 'text-slate-400 border-slate-700 bg-slate-800'
                        }`}
                      >
                        Riesgo {host.riskLevel}
                      </span>
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-800/40">
                        {host.operationalImportance}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 font-mono">
                      {host.ports.length} puerto{host.ports.length !== 1 ? 's' : ''} TCP abierto{host.ports.length !== 1 ? 's' : ''}
                    </div>
                  </div>

                  <div className="text-slate-400 p-1">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>
              </div>

              {/* Expanded details: Open ports, banners, risk explanation */}
              {isExpanded && (
                <div className="p-4 border-t border-slate-800/80 bg-slate-950/60 space-y-4 text-xs">
                  {/* Reasons summary */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                      <div className="text-[11px] uppercase tracking-wider text-cyan-400 font-semibold">
                        Justificación de Importancia Operativa
                      </div>
                      <ul className="list-disc list-inside text-slate-300 text-[11px] space-y-0.5">
                        {host.importanceReasons.map((r, idx) => (
                          <li key={idx}>{r}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                      <div className="text-[11px] uppercase tracking-wider text-amber-400 font-semibold">
                        Evaluación de Riesgo de Red
                      </div>
                      <ul className="list-disc list-inside text-slate-300 text-[11px] space-y-0.5">
                        {host.riskReasons.map((r, idx) => (
                          <li key={idx}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Services and banners table */}
                  <div className="space-y-2">
                    <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                      Servicios Escaneados y Banners Obtenidos
                    </div>

                    <div className="border border-slate-800 rounded overflow-hidden">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-medium">
                            <th className="py-2 px-3">Puerto</th>
                            <th className="py-2 px-3">Servicio</th>
                            <th className="py-2 px-3">Versión Divulgada</th>
                            <th className="py-2 px-3">Banner / Evidencia</th>
                            <th className="py-2 px-3 text-right">Acción</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {host.services.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="py-3 px-3 text-slate-400 text-center">
                                No se publicaron banners en los puertos detectados.
                              </td>
                            </tr>
                          ) : (
                            host.services.map((svc) => (
                              <tr key={svc.port} className="hover:bg-slate-900/40">
                                <td className="py-2 px-3 font-mono font-bold text-cyan-400">
                                  {svc.port}
                                </td>
                                <td className="py-2 px-3 font-medium text-slate-200">
                                  {svc.service}
                                </td>
                                <td className="py-2 px-3 font-mono text-[11px] text-slate-300">
                                  {svc.version || 'No divulgada'}
                                </td>
                                <td className="py-2 px-3 font-mono text-[11px] text-slate-400 max-w-sm truncate">
                                  {svc.banner || svc.evidence}
                                </td>
                                <td className="py-2 px-3 text-right">
                                  <button
                                    onClick={() => handleQuickAdd(host, svc.port)}
                                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 transition-colors"
                                  >
                                    <Plus className="w-3 h-3" />
                                    <span>Monitorear</span>
                                  </button>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
