import React, { useState, useMemo } from 'react';
import {
  AlertOctagon,
  Plus,
  Download,
  Search,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
} from 'lucide-react';
import { Incident, IncidentStatus, SeverityLevel } from '../types/security';
import { exportToCsv } from '../services/securityEngine';

interface IncidentsViewProps {
  incidents: Incident[];
  onCreateIncident: (incident: Omit<Incident, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateStatus: (id: string, status: IncidentStatus) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  onCreateIncident,
  onUpdateStatus,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | IncidentStatus>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form states
  const [formData, setFormData] = useState({
    title: '',
    category: 'Acceso no autorizado',
    description: '',
    assetName: '',
    assetIp: '',
    severity: 'high' as SeverityLevel,
  });

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesSearch =
        inc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.assetName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.assetIp.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === 'all' || inc.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [incidents, searchTerm, statusFilter]);

  const handleSubmitCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.title.trim() || !formData.description.trim()) return;

    onCreateIncident({
      title: formData.title.trim(),
      category: formData.category.trim(),
      description: formData.description.trim(),
      assetName: formData.assetName.trim(),
      assetIp: formData.assetIp.trim(),
      severity: formData.severity,
      status: 'open',
      reportedBy: 'Analista de Seguridad SOC',
    });

    setFormData({
      title: '',
      category: 'Acceso no autorizado',
      description: '',
      assetName: '',
      assetIp: '',
      severity: 'high',
    });
    setShowCreateModal(false);
  };

  const handleExportCsv = () => {
    const exportable = incidents.map((inc) => ({
      ID: inc.id,
      Titulo: inc.title,
      Categoria: inc.category,
      Severidad: inc.severity,
      Estado: inc.status,
      Activo: inc.assetName,
      IP_Activo: inc.assetIp,
      ReportadoPor: inc.reportedBy,
      FechaCreacion: inc.createdAt,
      FechaActualizacion: inc.updatedAt,
      Descripcion: inc.description,
    }));
    exportToCsv(exportable, 'registro-de-incidencias');
  };

  return (
    <div className="space-y-6">
      {/* Top Filter and Action Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded">
        <div className="flex flex-1 items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Buscar por título, activo, IP o categoría..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded">
            {(['all', 'open', 'investigating', 'resolved'] as const).map((st) => (
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
                  ? 'Todas'
                  : st === 'open'
                  ? 'Abiertas'
                  : st === 'investigating'
                  ? 'En Curso'
                  : 'Resueltas'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Crear Incidencia</span>
          </button>

          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
            title="Exportar a CSV"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Exportar CSV</span>
          </button>
        </div>
      </div>

      {/* Incidents List */}
      <div className="space-y-3">
        {filteredIncidents.length === 0 ? (
          <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded text-slate-400 text-xs">
            No hay incidencias registradas que coincidan con los filtros.
          </div>
        ) : (
          filteredIncidents.map((inc) => (
            <div
              key={inc.id}
              className={`p-4 rounded border transition-colors bg-slate-900 ${
                inc.severity === 'critical'
                  ? 'border-rose-900/60'
                  : inc.severity === 'high'
                  ? 'border-amber-900/60'
                  : 'border-slate-800'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border font-semibold ${
                        inc.severity === 'critical'
                          ? 'text-rose-400 border-rose-800/80 bg-rose-950/60'
                          : inc.severity === 'high'
                          ? 'text-amber-400 border-amber-800/80 bg-amber-950/60'
                          : 'text-cyan-400 border-cyan-800/80 bg-cyan-950/60'
                      }`}
                    >
                      {inc.severity}
                    </span>

                    <span className="text-xs font-bold text-slate-100">
                      {inc.title}
                    </span>

                    <span className="text-[11px] text-slate-400 font-mono">
                      (ID: {inc.id} · {inc.category})
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {inc.description}
                  </p>

                  <div className="flex items-center gap-3 text-[11px] text-slate-400 pt-1 font-mono flex-wrap">
                    <span>Activo afectado: <strong className="text-slate-200">{inc.assetName || 'General'}</strong></span>
                    {inc.assetIp && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span>IP: <strong className="text-cyan-400">{inc.assetIp}</strong></span>
                      </>
                    )}
                    <span aria-hidden="true">·</span>
                    <span>Reportado por: {inc.reportedBy}</span>
                    <span aria-hidden="true">·</span>
                    <span>Creado: {new Date(inc.createdAt).toLocaleString()}</span>
                  </div>
                </div>

                {/* Status Switcher */}
                <div className="shrink-0 flex items-center gap-2 self-start pt-1">
                  <span className="text-xs text-slate-400">Estado:</span>
                  <select
                    value={inc.status}
                    onChange={(e) => onUpdateStatus(inc.id, e.target.value as IncidentStatus)}
                    className={`bg-slate-950 border rounded px-2.5 py-1 text-xs font-semibold focus:outline-none ${
                      inc.status === 'open'
                        ? 'text-rose-400 border-rose-800'
                        : inc.status === 'investigating'
                        ? 'text-amber-400 border-amber-800'
                        : 'text-emerald-400 border-emerald-800'
                    }`}
                  >
                    <option value="open">Abierta</option>
                    <option value="investigating">En Investigación</option>
                    <option value="resolved">Resuelta</option>
                  </select>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Modal: Create Incident */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Registrar Nueva Incidencia de Seguridad
            </h3>

            <form onSubmit={handleSubmitCreate} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Título de la Incidencia *
                </label>
                <input
                  type="text"
                  required
                  placeholder="ej. Intento de explotación en puerto 445"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Categoría
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    <option value="Acceso no autorizado">Acceso no autorizado</option>
                    <option value="Persistencia / Malware">Persistencia / Malware</option>
                    <option value="Shadow IT / Acceso Remoto">Shadow IT / Acceso Remoto</option>
                    <option value="Transporte inseguro">Transporte inseguro</option>
                    <option value="Criptografía / Certificados">Criptografía / Certificados</option>
                    <option value="Fuga de Información">Fuga de Información</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Nivel de Severidad
                  </label>
                  <select
                    value={formData.severity}
                    onChange={(e) =>
                      setFormData({ ...formData, severity: e.target.value as SeverityLevel })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Nombre del Activo
                  </label>
                  <input
                    type="text"
                    placeholder="DC01-CARIOCA"
                    value={formData.assetName}
                    onChange={(e) => setFormData({ ...formData, assetName: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Dirección IP del Activo
                  </label>
                  <input
                    type="text"
                    placeholder="10.0.0.22"
                    value={formData.assetIp}
                    onChange={(e) => setFormData({ ...formData, assetIp: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Descripción y Evidencia *
                </label>
                <textarea
                  rows={4}
                  required
                  placeholder="Detalla el hallazgo, eventos relacionados y medidas de contención requeridas..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200 font-medium"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-slate-950 font-bold bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                >
                  Guardar Incidencia
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
