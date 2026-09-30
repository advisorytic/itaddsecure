import React from 'react';
import {
  Activity,
  Search,
  Network,
  Binary,
  AlertOctagon,
  Globe2,
  Cpu,
  Layers,
} from 'lucide-react';

export type ActiveTab =
  | 'endpoints'
  | 'hunting'
  | 'network'
  | 'ad-dns'
  | 'incidents'
  | 'osint'
  | 'shadow-ai'
  | 'modules';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  incidentsCount: number;
  threatsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  incidentsCount,
  threatsCount,
}) => {
  const menuItems = [
    {
      id: 'endpoints' as ActiveTab,
      label: 'Salud de Endpoints',
      icon: Activity,
      badge: null,
      desc: 'Monitoreo HTTP/HTTPS y latencia',
    },
    {
      id: 'hunting' as ActiveTab,
      label: 'Caza de Amenazas & Logs',
      icon: Search,
      badge: threatsCount > 0 ? threatsCount : null,
      badgeColor: 'text-amber-400 bg-amber-950/80 border-amber-800/40',
      desc: 'Eventos Windows, fuerza bruta y persistencia',
    },
    {
      id: 'network' as ActiveTab,
      label: 'Descubrimiento de Red',
      icon: Network,
      badge: null,
      desc: 'Escaneo CIDR y banners de puertos',
    },
    {
      id: 'ad-dns' as ActiveTab,
      label: 'Correlación AD-DS / DNS',
      icon: Binary,
      badge: null,
      desc: 'Validación LDAP RootDSE y registros SRV/PTR',
    },
    {
      id: 'incidents' as ActiveTab,
      label: 'Gestión de Incidentes',
      icon: AlertOctagon,
      badge: incidentsCount > 0 ? incidentsCount : null,
      badgeColor: 'text-rose-400 bg-rose-950/80 border-rose-800/40',
      desc: 'Seguimiento, triage y exportación CSV',
    },
    {
      id: 'osint' as ActiveTab,
      label: 'Inteligencia OSINT de IP',
      icon: Globe2,
      badge: null,
      desc: 'Consultas pasivas RDAP y ASN públicas',
    },
    {
      id: 'shadow-ai' as ActiveTab,
      label: 'Auditoría de Shadow AI',
      icon: Cpu,
      badge: null,
      desc: 'Detección prudente de modelos y frameworks',
    },
    {
      id: 'modules' as ActiveTab,
      label: 'Módulos EDR / IDS / NDR',
      icon: Layers,
      badge: null,
      desc: 'F5 BIG-IP, EDR local y telemetría unificada',
    },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0">
      <div className="p-4 border-b border-slate-800">
        <div className="text-xs uppercase tracking-wider font-semibold text-slate-400 mb-1">
          Navegación Operativa
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Centro de Operaciones de Seguridad (SOC)
        </p>
      </div>

      <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full text-left px-3 py-2.5 rounded text-xs font-medium transition-colors flex items-center justify-between group ${
                isActive
                  ? 'bg-slate-800 text-cyan-300 border-l-2 border-cyan-400 shadow-sm'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Icon
                  className={`w-4 h-4 shrink-0 ${
                    isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'
                  }`}
                />
                <div className="truncate">
                  <div className="truncate">{item.label}</div>
                  <div className="text-slate-400 text-[11px] truncate font-normal">
                    {item.desc}
                  </div>
                </div>
              </div>

              {item.badge !== null && (
                <span
                  className={`ml-2 px-1.5 py-0.5 rounded text-[11px] font-mono tabular-nums border shrink-0 ${
                    item.badgeColor || 'text-slate-300 bg-slate-800 border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Target Infrastructure Quick Note */}
      <div className="p-3 m-2 bg-slate-950/70 border border-slate-800 rounded text-xs space-y-1">
        <div className="text-slate-400 font-medium">Objetivo Validado</div>
        <div className="font-mono text-cyan-400 text-[11px]">10.0.0.22 (DC01)</div>
        <div className="text-[11px] text-slate-400">LDAP & DNS Correlacionado</div>
      </div>
    </aside>
  );
};
