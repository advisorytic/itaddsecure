import React from 'react';
import {
  Layers,
  Shield,
  Activity,
  Server,
  Network,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { SecurityModuleStatus } from '../types/security';

interface SecurityModulesViewProps {
  modules: SecurityModuleStatus[];
}

export const SecurityModulesView: React.FC<SecurityModulesViewProps> = ({ modules }) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          Arquitectura de Módulos de Defensa en Profundidad
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Integración de componentes perimetrales (F5 BIG-IP), agentes de host (EDR), detección de intrusos (IDS) y telemetría de red (NDR)
        </p>
      </div>

      {/* Grid of 4 Security Modules */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {modules.map((mod) => (
          <div
            key={mod.key}
            className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col justify-between space-y-3"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-100">{mod.name}</span>
                <span
                  className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border font-semibold ${
                    mod.status === 'active' || mod.status === 'configured'
                      ? 'text-emerald-400 border-emerald-800/80 bg-emerald-950/60'
                      : 'text-slate-400 border-slate-700 bg-slate-800'
                  }`}
                >
                  {mod.status === 'configured' ? 'Configurado' : mod.status === 'active' ? 'Activo' : 'Inactivo'}
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed text-[11px]">
                {mod.detail}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs text-slate-400 font-mono">
              <span>Eventos procesados:</span>
              <strong className="text-cyan-400 tabular-nums">{mod.eventCount}</strong>
            </div>
          </div>
        ))}
      </div>

      {/* Deep Dive Architecture Card */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 space-y-4 text-xs">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider">
          Mecanismo de Alerta Crítica SMTP Integrado
        </h3>
        <p className="text-slate-300 leading-relaxed">
          El subsistema de despacho envía notificaciones SMTP hacia <code className="text-cyan-400 font-mono">smtp.carioca.com.do:25</code> al destinatario <code className="text-cyan-400 font-mono">rramirez@carioca.com.do</code> en caso de detección de incidentes con criticidad extrema. Dispone de un mecanismo de token bucket anti-inundación con una ventana de enfriamiento de <strong className="text-slate-100 font-mono">900 segundos (15 minutos)</strong> para prevenir ruidos repetitivos en la bandeja de entrada del SOC.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-[11px] font-mono">
          <div className="p-3 bg-slate-950 border border-slate-800 rounded">
            <span className="text-slate-400 block mb-0.5">Servidor de Salida SMTP:</span>
            <span className="text-slate-200">smtp.carioca.com.do:25</span>
          </div>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded">
            <span className="text-slate-400 block mb-0.5">Destinatario Crítico:</span>
            <span className="text-cyan-400">rramirez@carioca.com.do</span>
          </div>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded">
            <span className="text-slate-400 block mb-0.5">Cooldown Anti-Flood:</span>
            <span className="text-emerald-400">15 Minutos por Huella</span>
          </div>
        </div>
      </div>
    </div>
  );
};
