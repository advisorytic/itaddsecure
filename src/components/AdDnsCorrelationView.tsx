import React, { useState } from 'react';
import {
  Binary,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Server,
  ShieldCheck,
  AlertCircle,
  Network,
} from 'lucide-react';
import { DnsAdCorrelationResult } from '../types/security';

interface AdDnsCorrelationViewProps {
  correlation: DnsAdCorrelationResult;
  onRevalidate: (serverIp: string) => void;
  isValidating: boolean;
}

export const AdDnsCorrelationView: React.FC<AdDnsCorrelationViewProps> = ({
  correlation,
  onRevalidate,
  isValidating,
}) => {
  const [targetIp, setTargetIp] = useState(correlation.serverIp || '10.0.0.22');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetIp.trim()) {
      onRevalidate(targetIp.trim());
    }
  };

  return (
    <div className="space-y-6">
      {/* Target input header */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4">
        <form onSubmit={handleSubmit} className="flex flex-col md:flex-row items-stretch md:items-end justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Binary className="w-4 h-4 text-cyan-400" />
              Correlación Cruzada DNS / Active Directory Domain Services (AD-DS)
            </h2>
            <p className="text-xs text-slate-400">
              Validación criptográfica y funcional de identidad entre el servidor DNS interno y el controlador ADSI
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">
                IP del Servidor Objetivo (DNS / AD-DS)
              </label>
              <input
                type="text"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="10.0.0.22"
                className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-cyan-400 font-mono focus:outline-none focus:border-cyan-500/60"
              />
            </div>

            <button
              type="submit"
              disabled={isValidating}
              className="flex items-center gap-2 px-4 py-1.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-60 whitespace-nowrap mt-4 md:mt-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isValidating ? 'animate-spin' : ''}`} />
              <span>{isValidating ? 'Consultando...' : 'Validar Correlación'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Confirmation Banner */}
      <div
        className={`p-4 rounded border flex items-center justify-between gap-4 ${
          correlation.sameServerConfirmed
            ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
            : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
        }`}
      >
        <div className="flex items-center gap-3">
          {correlation.sameServerConfirmed ? (
            <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
          ) : (
            <AlertCircle className="w-6 h-6 text-rose-400 shrink-0" />
          )}
          <div>
            <div className="text-xs font-bold uppercase tracking-wider">
              {correlation.sameServerConfirmed
                ? 'Coincidencia de Mismo Servidor Confirmada'
                : 'Fallo de Correlación: Discrepancia entre DNS y AD-DS'}
            </div>
            <p className="text-xs opacity-90 leading-relaxed">
              {correlation.sameServerConfirmed
                ? `La dirección ${correlation.serverIp} aloja de forma legítima y sincrónica el servicio DNS RFC1035 y el directorio AD-DS del dominio '${correlation.domainName}'.`
                : correlation.dnsError || correlation.adError || 'Uno de los componentes no respondió a la consulta de verificación.'}
            </p>
          </div>
        </div>

        <div className="text-right font-mono text-[11px] opacity-75 shrink-0 hidden sm:block">
          <div>Comprobado: {correlation.checkedAt ? new Date(correlation.checkedAt).toLocaleTimeString() : 'N/A'}</div>
          <div>Código DNS RCODE: {correlation.dnsResponseCode ?? '0'}</div>
        </div>
      </div>

      {/* Two Column Layout: DNS Service vs AD-DS Service */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left Column: DNS Side */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Respuesta del Servidor DNS (Puerto 53)
              </h3>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              {correlation.dnsResponded ? (
                <span className="text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Respondió</span>
                </span>
              ) : (
                <span className="text-rose-400 flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Sin Respuesta</span>
                </span>
              )}
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Resolución Inversa PTR ({correlation.serverIp}.in-addr.arpa):
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 text-[11px]">
                {correlation.ptrNames.length > 0
                  ? correlation.ptrNames.join(', ')
                  : 'Sin registro PTR'}
              </div>
            </div>

            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Resolución Directa A (Coincidencia con IP Objetivo):
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] flex items-center justify-between">
                <span className="text-slate-200">
                  {correlation.forwardAddresses.length > 0
                    ? correlation.forwardAddresses.join(', ')
                    : 'Sin registros A'}
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${
                    correlation.dnsForwardMatchesServerIp
                      ? 'text-emerald-400 border-emerald-800/60 bg-emerald-950/60'
                      : 'text-amber-400 border-amber-800/60 bg-amber-950/60'
                  }`}
                >
                  {correlation.dnsForwardMatchesServerIp ? 'IP Coincide' : 'Difiere'}
                </span>
              </div>
            </div>

            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Registros SRV Localizadores de DC (_ldap._tcp.dc._msdcs):
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-slate-300 text-[11px] space-y-1">
                {correlation.srvRecords.map((srv, idx) => (
                  <div key={idx} className="flex justify-between items-center">
                    <span className="text-cyan-400">{srv.value}</span>
                    <span className="text-slate-400">Puerto {srv.port}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: AD-DS / LDAP Side */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Respuesta Active Directory (LDAP / ADSI)
              </h3>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              {correlation.adServerResponded ? (
                <span className="text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Respondió</span>
                </span>
              ) : (
                <span className="text-rose-400 flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Fallo</span>
                </span>
              )}
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Nombre de Dominio AD-DS (defaultNamingContext):
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 text-[11px]">
                {correlation.domainName || 'No disponible'}
              </div>
            </div>

            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Controladores de Dominio Registrados:
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] space-y-1">
                {correlation.domainControllers.map((dc, idx) => (
                  <div key={idx} className="flex justify-between items-center text-slate-300">
                    <span className="font-semibold text-slate-100">{dc.name}</span>
                    <span className="text-cyan-400">{dc.hostName}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] text-slate-400 font-medium mb-1">
                Coincidencia Cruzada de Objeto Computadora / DC:
              </div>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-[11px]">
                {correlation.matchingDomainControllers.length > 0 ? (
                  <div className="text-emerald-300">
                    ✓ Validado: {correlation.matchingDomainControllers.map((c) => `${c.name} (${c.hostName})`).join(', ')}
                  </div>
                ) : (
                  <div className="text-amber-400">
                    ⚠ Ningún controlador de dominio coincide exactamente con la dirección {correlation.serverIp}.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
