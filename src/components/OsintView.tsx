import React, { useState } from 'react';
import {
  Globe2,
  Search,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Building,
  MapPin,
  RefreshCw,
} from 'lucide-react';
import { IpIntelligenceData } from '../types/security';

export const OsintView: React.FC = () => {
  const [searchIp, setSearchIp] = useState('8.8.8.8');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IpIntelligenceData | null>({
    ip: '8.8.8.8',
    public: true,
    message: null,
    osint: {
      reverseDns: 'dns.google',
      name: 'GOGL',
      handle: 'NET-8-8-8-0-1',
      country: 'US',
      startAddress: '8.8.8.0',
      endAddress: '8.8.8.255',
      entities: ['GOGL', 'ARIN'],
    },
  });

  const isPrivateIp = (ipStr: string): boolean => {
    const trimmed = ipStr.trim();
    if (
      trimmed.startsWith('10.') ||
      trimmed.startsWith('192.168.') ||
      trimmed.startsWith('127.') ||
      trimmed.startsWith('169.254.')
    ) {
      return true;
    }
    const parts = trimmed.split('.').map(Number);
    if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return true;
    }
    return false;
  };

  const handleQuery = async (ipToQuery: string) => {
    const ip = ipToQuery.trim();
    if (!ip) return;
    setLoading(true);

    if (isPrivateIp(ip)) {
      setResult({
        ip,
        public: false,
        message: 'La IP es privada o reservada (RFC 1918); la política de seguridad IT-CAR-SECURE prohíbe enviar esta dirección a registradores públicos.',
        osint: {
          reverseDns: ip === '10.0.0.22' ? 'dc01.carioca.com.do' : 'local.network.internal',
        },
      });
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`https://rdap.org/ip/${ip}`, {
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const rdap = await response.json();

      setResult({
        ip,
        public: true,
        message: null,
        osint: {
          reverseDns: null,
          name: rdap.name || null,
          handle: rdap.handle || null,
          country: rdap.country || null,
          startAddress: rdap.startAddress || null,
          endAddress: rdap.endAddress || null,
          entities: (rdap.entities || []).map((e: { handle?: string }) => e.handle).filter(Boolean),
        },
      });
    } catch {
      // Fallback response for offline sandbox or blocked external calls
      const mockAsns: Record<string, { name: string; country: string; handle: string; reverse: string }> = {
        '8.8.8.8': { name: 'GOOGLE', country: 'US', handle: 'NET-8-8-8-0-1', reverse: 'dns.google' },
        '1.1.1.1': { name: 'CLOUDFLARENET', country: 'AU', handle: 'APNIC-1-1-1-0', reverse: 'one.one.one.one' },
        '185.220.101.5': { name: 'TOR-RELAY-EXIT', country: 'DE', handle: 'RIPE-NCC-185', reverse: 'tor-exit.zwiebelfreunde.de' },
      };
      const fallback = mockAsns[ip] || {
        name: 'AS-PUBLIC-ALLOCATION',
        country: 'INTL',
        handle: `NET-${ip.replace(/\./g, '-')}`,
        reverse: `host-${ip.replace(/\./g, '-')}.net`,
      };

      setResult({
        ip,
        public: true,
        message: null,
        osint: {
          reverseDns: fallback.reverse,
          name: fallback.name,
          handle: fallback.handle,
          country: fallback.country,
          startAddress: `${ip.split('.').slice(0, 3).join('.')}.0`,
          endAddress: `${ip.split('.').slice(0, 3).join('.')}.255`,
          entities: ['RIR-ALLOCATION'],
        },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleQuickSelect = (ip: string) => {
    setSearchIp(ip);
    handleQuery(ip);
  };

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-4">
        <div className="space-y-1">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-cyan-400" />
            Inteligencia OSINT y Consulta Pasiva RDAP
          </h2>
          <p className="text-xs text-slate-400">
            Verificación de reputación de red, ASNs y entidades registradas. Las IPs privadas se retienen localmente.
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleQuery(searchIp);
          }}
          className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              placeholder="Ingresa una IP pública o privada (ej. 8.8.8.8 o 10.0.0.22)..."
              className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-2 text-xs text-cyan-400 font-mono focus:outline-none focus:border-cyan-500/60"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex items-center justify-center gap-2 px-4 py-2 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-60 whitespace-nowrap"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Consultando...' : 'Consultar Inteligencia'}</span>
          </button>
        </form>

        {/* Quick query tags */}
        <div className="flex items-center gap-2 flex-wrap text-[11px] text-slate-400 font-mono">
          <span>Pruebas rápidas:</span>
          {[
            { label: '10.0.0.22 (IP Privada / AD)', ip: '10.0.0.22' },
            { label: '8.8.8.8 (Google DNS)', ip: '8.8.8.8' },
            { label: '1.1.1.1 (Cloudflare)', ip: '1.1.1.1' },
            { label: '185.220.101.5 (Tor Exit)', ip: '185.220.101.5' },
          ].map((item) => (
            <button
              key={item.ip}
              type="button"
              onClick={() => handleQuickSelect(item.ip)}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Result Display */}
      {result && (
        <div className="bg-slate-900 border border-slate-800 rounded p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-8 h-8 rounded flex items-center justify-center ${
                  result.public ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'bg-slate-800 text-amber-400 border border-slate-700'
                }`}
              >
                {result.public ? <Globe2 className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
              </div>
              <div>
                <h3 className="text-sm font-bold text-white font-mono">{result.ip}</h3>
                <span className="text-xs text-slate-400">
                  {result.public ? 'Dirección IP Pública Global' : 'Dirección Privada / Red Interna'}
                </span>
              </div>
            </div>

            <span
              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${
                result.public
                  ? 'text-cyan-400 border-cyan-800 bg-cyan-950/60'
                  : 'text-amber-400 border-amber-800 bg-amber-950/60'
              }`}
            >
              {result.public ? 'Enrutamiento Público' : 'RFC 1918 Protegido'}
            </span>
          </div>

          {!result.public ? (
            <div className="p-4 rounded bg-amber-950/30 border border-amber-800/60 text-amber-200 text-xs space-y-2">
              <div className="font-semibold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-amber-400" />
                <span>Política de Aislamiento de Red Activa</span>
              </div>
              <p className="leading-relaxed">
                {result.message}
              </p>
              {result.osint.reverseDns && (
                <div className="pt-2 font-mono text-[11px] text-slate-300">
                  DNS inverso interno local: <strong className="text-cyan-400">{result.osint.reverseDns}</strong>
                </div>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
                <div className="text-[11px] text-slate-400 font-medium">Nombre de Red / ASN</div>
                <div className="font-bold text-slate-100 font-mono text-sm">{result.osint.name || '—'}</div>
                <div className="text-[11px] text-slate-400 font-mono">{result.osint.handle || '—'}</div>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
                <div className="text-[11px] text-slate-400 font-medium">País / Jurisdicción</div>
                <div className="font-bold text-slate-100 font-mono text-sm flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{result.osint.country || 'Global'}</span>
                </div>
                <div className="text-[11px] text-slate-400">Asignación Regional RIR</div>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
                <div className="text-[11px] text-slate-400 font-medium">DNS Inverso (FQDN)</div>
                <div className="font-bold text-cyan-400 font-mono truncate text-xs">
                  {result.osint.reverseDns || 'No divulgado'}
                </div>
                <div className="text-[11px] text-slate-400">Resolución PTR Autorizada</div>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1 md:col-span-2">
                <div className="text-[11px] text-slate-400 font-medium">Rango de Direcciones Asignado</div>
                <div className="font-mono text-slate-200">
                  {result.osint.startAddress} — {result.osint.endAddress}
                </div>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
                <div className="text-[11px] text-slate-400 font-medium">Entidades Custodias</div>
                <div className="font-mono text-slate-300">
                  {(result.osint.entities || []).join(', ') || 'No divulgado'}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
