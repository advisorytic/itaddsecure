import React, { useState } from 'react';
import {
  Cpu,
  Upload,
  AlertTriangle,
  Info,
  CheckCircle,
  FileSpreadsheet,
} from 'lucide-react';
import { AiIndicatorItem } from '../types/security';
import { analyzeInventoryAi, parseDelimitedText } from '../services/securityEngine';

const SAMPLE_INVENTORY = [
  {
    ip: '10.0.0.52',
    name: 'WS-DEV-AI-01',
    hostname: 'dev-station-ollama.carioca.corp',
    manufacturer: 'NVIDIA RTX Workstation',
    deviceType: 'Desarrollo / Machine Learning',
    description: 'Servicio ollama local y entorno python cuda para pruebas de modelos locales',
  },
  {
    ip: '10.0.0.53',
    name: 'WS-DATA-02',
    hostname: 'jupyter-node.carioca.corp',
    manufacturer: 'Dell Precision',
    deviceType: 'Estación de Analítica',
    description: 'Servidor jupyter notebook con librerias pytorch y huggingface',
  },
  {
    ip: '10.0.0.70',
    name: 'PC-MARKETING-05',
    hostname: 'mkt-user-05.carioca.corp',
    manufacturer: 'Lenovo ThinkPad',
    deviceType: 'Equipo Portátil',
    description: 'Extensión chatgpt y copilot instalada en navegador edge',
  },
  {
    ip: '10.0.0.22',
    name: 'DC01-CARIOCA',
    hostname: 'dc01.carioca.com.do',
    manufacturer: 'Microsoft Hyper-V',
    deviceType: 'Controlador de Dominio',
    description: 'Windows Server 2022 Active Directory y DNS sin software accesorio',
  },
  {
    ip: '10.0.0.45',
    name: 'SQL-CORE-PROD',
    hostname: 'sql01.carioca.com.do',
    manufacturer: 'VMware',
    deviceType: 'Servidor de Base de Datos',
    description: 'Motor transaccional SQL Server sin herramientas de IA',
  },
];

export const AiUsageDetectorView: React.FC = () => {
  const [inventory, setInventory] = useState<Array<Record<string, unknown>>>(SAMPLE_INVENTORY);
  const [csvInput, setCsvInput] = useState('');
  const [showImport, setShowImport] = useState(false);

  const findings: AiIndicatorItem[] = analyzeInventoryAi(inventory);

  const handleImportCsv = (e: React.FormEvent) => {
    e.preventDefault();
    if (!csvInput.trim()) return;
    try {
      const parsed = parseDelimitedText(csvInput);
      if (parsed.length > 0) {
        setInventory(parsed);
        setShowImport(false);
        setCsvInput('');
      }
    } catch {
      // Handled
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Disclaimers */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Auditoría Prudente de Shadow AI y Frameworks en Inventario
            </h2>
            <p className="text-xs text-slate-400">
              Detección de artefactos (OpenAI, ChatGPT, Copilot, Ollama, PyTorch, CUDA, Claude, Hugging Face)
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowImport(!showImport)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
            >
              <Upload className="w-3.5 h-3.5 text-slate-400" />
              <span>Importar CSV de Inventario</span>
            </button>
            <button
              onClick={() => setInventory(SAMPLE_INVENTORY)}
              className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors whitespace-nowrap"
            >
              Restaurar
            </button>
          </div>
        </div>

        {/* Essential SOC Guidance Note */}
        <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded flex items-start gap-3 text-xs text-cyan-200">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1 leading-relaxed">
            <span className="font-semibold text-cyan-300">
              Principio de Prudencia Operativa SOC:
            </span>
            <p className="text-slate-300 text-[11px]">
              La presencia de un indicador en el inventario o nombre de host <strong>no demuestra por sí sola un uso abusivo o fuga de datos</strong>.
              Sirve como señal de visibilidad para auditar consumo de cómputo, telemetría de red saliente hacia APIs de LLM y confirmar si la actividad cuenta con autorización del área de tecnología.
            </p>
          </div>
        </div>
      </div>

      {/* CSV Import drawer */}
      {showImport && (
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-3">
          <span className="text-xs font-semibold text-white">
            Pega tu inventario de equipos (columnas: ip, name, hostname, manufacturer, description)
          </span>
          <form onSubmit={handleImportCsv} className="space-y-3">
            <textarea
              rows={4}
              value={csvInput}
              onChange={(e) => setCsvInput(e.target.value)}
              placeholder={`ip,name,description\n10.0.0.90,WS-DEV,Equipo con entorno local de ollama y llama3\n10.0.0.91,WS-FIN,Estacion contable`}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
            />
            <div className="flex justify-end gap-2">
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
              >
                Analizar Inventario
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Findings List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span>Equipos con indicadores de IA: <strong className="text-amber-400 tabular-nums">{findings.length}</strong></span>
          <span>Total evaluados: {inventory.length}</span>
        </div>

        {findings.length === 0 ? (
          <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded text-slate-400 text-xs">
            No se identificaron patrones de software de Inteligencia Artificial en el inventario analizado.
          </div>
        ) : (
          findings.map((item) => (
            <div
              key={item.id}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded p-4 space-y-2 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-100">{item.name}</span>
                  <span className="font-mono text-xs text-cyan-400 tabular-nums">({item.ip})</span>
                  <span
                    className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                      item.severity === 'high'
                        ? 'text-amber-400 border-amber-800 bg-amber-950/60'
                        : 'text-cyan-400 border-cyan-800 bg-cyan-950/60'
                    }`}
                  >
                    Atención {item.severity}
                  </span>
                </div>

                {/* Badges of matched terms */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {item.indicators.map((ind) => (
                    <span
                      key={ind}
                      className="px-2 py-0.5 rounded text-[11px] font-mono text-cyan-300 bg-slate-950 border border-cyan-900/60"
                    >
                      {ind}
                    </span>
                  ))}
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-mono text-[11px]">
                {item.detail}
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
