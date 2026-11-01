import React, { useState } from 'react';
import { Terminal, Cpu, ShieldCheck, Wrench, X, Maximize2, Minimize2, Activity, Database, Package } from 'lucide-react';

export interface SystemMetrics {
  gpu: {
    name: string;
    utilization: number;
    memoryUsedMb: number;
    memoryTotalMb: number;
    temperatureC: number;
  };
  cpu: {
    cores: number;
    load1m: number;
    memoryUsedMb: number;
    memoryTotalMb: number;
    memoryPercent: number;
  };
}

interface TabLogs {
  vllm: string[];
  scan: string[];
  fix: string[];
  cve8080?: string[];
  sca8082?: string[];
}

export const CyberTerminalTabs: React.FC<{
  logs: TabLogs;
  metrics: SystemMetrics | null;
  isOpen: boolean;
  onClose: () => void;
}> = ({ logs, metrics, isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'scan' | 'vllm' | 'fix' | 'cve8080' | 'sca8082' | 'hardware'>('scan');
  const [expanded, setExpanded] = useState(false);

  if (!isOpen) return null;

  const currentLogArray = activeTab !== 'hardware' ? logs[activeTab] || [] : [];

  return (
    <div style={{
      position: 'fixed',
      bottom: 0,
      left: 0,
      right: 0,
      height: expanded ? '70vh' : '280px',
      background: '#01040d',
      borderTop: '2px solid #00f0ff',
      boxShadow: '0 -8px 30px rgba(0, 240, 255, 0.25)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 100,
      transition: 'height 0.25s ease'
    }}>
      {/* Tab Navigation Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        background: '#040d21',
        borderBottom: '1px solid rgba(0, 240, 255, 0.2)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginRight: '16px', color: '#00f0ff', fontSize: '0.8rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '0.05em' }}>
            <Terminal size={15} />
            <span>QBIT // KERNEL CONSOLE</span>
          </div>

          <button
            onClick={() => setActiveTab('scan')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'scan' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'scan' ? '2px solid #00f0ff' : '2px solid transparent',
              color: activeTab === 'scan' ? '#00f0ff' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <ShieldCheck size={13} />
            QBIT SCAN STREAM
            <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.1)', color: '#38bdf8' }}>
              {logs.scan.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('vllm')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'vllm' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'vllm' ? '2px solid #00f0ff' : '2px solid transparent',
              color: activeTab === 'vllm' ? '#00f0ff' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <Cpu size={13} />
            vLLM H100 ENGINE
            <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.1)', color: '#38bdf8' }}>
              {logs.vllm.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('fix')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'fix' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'fix' ? '2px solid #00f0ff' : '2px solid transparent',
              color: activeTab === 'fix' ? '#00f0ff' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <Wrench size={13} />
            REMEDIATION AGENT
            <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.1)', color: '#38bdf8' }}>
              {logs.fix.length}
            </span>
          </button>

          {/* CVE/CWE Vector Server 8080 Console */}
          <button
            onClick={() => setActiveTab('cve8080')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'cve8080' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'cve8080' ? '2px solid #00f0ff' : '2px solid transparent',
              color: activeTab === 'cve8080' ? '#00f0ff' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <Database size={13} color="#38bdf8" />
            CVE/CWE ENRICHER (:8080)
            <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.1)', color: '#38bdf8' }}>
              {logs.cve8080?.length || 0}
            </span>
          </button>

          {/* SCA Universal Dependency Scanner 8082 Console */}
          <button
            onClick={() => setActiveTab('sca8082')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'sca8082' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'sca8082' ? '2px solid #f59e0b' : '2px solid transparent',
              color: activeTab === 'sca8082' ? '#fbbf24' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <Package size={13} color="#fbbf24" />
            SCA PACKAGES (:8082)
            <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24' }}>
              {logs.sca8082?.length || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('hardware')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: activeTab === 'hardware' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'hardware' ? '2px solid #00f0ff' : '2px solid transparent',
              color: activeTab === 'hardware' ? '#00f0ff' : '#64748b',
              cursor: 'pointer',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.78rem',
              fontWeight: 600
            }}>
            <Activity size={13} />
            HARDWARE TELEMETRY (GPU/CPU)
            {metrics?.gpu && (
              <span style={{ fontSize: '0.7rem', padding: '1px 5px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.15)', color: '#00f0ff' }}>
                {metrics.gpu.utilization}% GPU
              </span>
            )}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: '4px' }}
            title={expanded ? 'Minimize' : 'Maximize'}>
            {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: '4px' }}>
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Terminal Content or Hardware Dashboard */}
      {activeTab === 'hardware' ? (
        <div style={{
          flex: 1,
          overflowY: 'auto',
          padding: '20px 24px',
          background: 'rgba(0, 0, 0, 0.75)',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '24px'
        }}>
          {/* GPU Telemetry Card */}
          <div style={{
            background: '#030816',
            border: '1px solid rgba(0, 240, 255, 0.3)',
            borderRadius: '8px',
            padding: '16px',
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.1)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(0, 240, 255, 0.15)', paddingBottom: '10px', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'Orbitron, sans-serif', color: '#00f0ff', fontSize: '0.85rem' }}>
                <Cpu size={16} />
                <span>NVIDIA ACCELERATOR</span>
              </div>
              <span style={{ fontSize: '0.75rem', fontFamily: '"JetBrains Mono", monospace', color: '#38bdf8' }}>
                {metrics?.gpu?.name || 'H100 NVL'}
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>
                  <span>Compute Core Utilization</span>
                  <span style={{ color: '#00f0ff', fontWeight: 'bold' }}>{metrics?.gpu?.utilization ?? 0}%</span>
                </div>
                <div style={{ width: '100%', height: '8px', background: '#020612', borderRadius: '4px', overflow: 'hidden', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                  <div style={{ width: `${metrics?.gpu?.utilization ?? 0}%`, height: '100%', background: 'linear-gradient(90deg, #0070f3, #00f0ff)', boxShadow: '0 0 10px #00f0ff' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>
                  <span>VRAM Consumption</span>
                  <span style={{ color: '#00f0ff', fontWeight: 'bold' }}>
                    {Math.round((metrics?.gpu?.memoryUsedMb || 0) / 1024)} GB / {Math.round((metrics?.gpu?.memoryTotalMb || 95830) / 1024)} GB
                  </span>
                </div>
                <div style={{ width: '100%', height: '8px', background: '#020612', borderRadius: '4px', overflow: 'hidden', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                  <div style={{
                    width: `${Math.round(((metrics?.gpu?.memoryUsedMb || 0) / (metrics?.gpu?.memoryTotalMb || 95830)) * 100)}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #0070f3, #38bdf8)'
                  }} />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px', fontSize: '0.78rem', color: '#64748b' }}>
                <span>Thermal: <strong style={{ color: '#e0f2fe' }}>{metrics?.gpu?.temperatureC || 0}°C</strong></span>
                <span>PCIe Bus: <strong style={{ color: '#00f0ff' }}>Gen5 x16</strong></span>
              </div>
            </div>
          </div>

          {/* CPU & System Memory Card */}
          <div style={{
            background: '#030816',
            border: '1px solid rgba(0, 240, 255, 0.3)',
            borderRadius: '8px',
            padding: '16px',
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.1)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(0, 240, 255, 0.15)', paddingBottom: '10px', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'Orbitron, sans-serif', color: '#00f0ff', fontSize: '0.85rem' }}>
                <Activity size={16} />
                <span>HOST SYSTEM RESOURCE</span>
              </div>
              <span style={{ fontSize: '0.75rem', fontFamily: '"JetBrains Mono", monospace', color: '#38bdf8' }}>
                {metrics?.cpu?.cores || 42} Physical Cores
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>
                  <span>System Load Average (1m)</span>
                  <span style={{ color: '#00f0ff', fontWeight: 'bold' }}>{metrics?.cpu?.load1m?.toFixed(2) ?? '0.00'}</span>
                </div>
                <div style={{ width: '100%', height: '8px', background: '#020612', borderRadius: '4px', overflow: 'hidden', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                  <div style={{
                    width: `${Math.min(100, ((metrics?.cpu?.load1m || 0) / (metrics?.cpu?.cores || 42)) * 100)}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #0070f3, #00f0ff)'
                  }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>
                  <span>Host RAM Allocation</span>
                  <span style={{ color: '#00f0ff', fontWeight: 'bold' }}>
                    {Math.round((metrics?.cpu?.memoryUsedMb || 0) / 1024)} GB / {Math.round((metrics?.cpu?.memoryTotalMb || 0) / 1024)} GB ({metrics?.cpu?.memoryPercent || 0}%)
                  </span>
                </div>
                <div style={{ width: '100%', height: '8px', background: '#020612', borderRadius: '4px', overflow: 'hidden', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                  <div style={{
                    width: `${metrics?.cpu?.memoryPercent || 0}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #0070f3, #38bdf8)'
                  }} />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px', fontSize: '0.78rem', color: '#64748b' }}>
                <span>Host Status: <strong style={{ color: '#38bdf8' }}>ONLINE</strong></span>
                <span>Active Processors: <strong style={{ color: '#00f0ff' }}>{metrics?.cpu?.cores || 42} Threads</strong></span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 18px',
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: '0.78rem',
          color: '#bae6fd',
          lineHeight: 1.6,
          background: 'rgba(0, 0, 0, 0.75)'
        }}>
          {currentLogArray.length === 0 ? (
            <div style={{ color: '#475569', fontStyle: 'italic', padding: '16px 0' }}>
              [SYSTEM STANDBY] Listening for {activeTab.toUpperCase()} stream events...
            </div>
          ) : (
            currentLogArray.map((line, i) => (
              <div key={i} style={{
                display: 'flex',
                gap: '8px',
                color: line.includes('error') || line.includes('ERR') || line.includes('400') ? '#f87171' : line.includes('✔') || line.includes('OK') || line.includes('200') ? '#00f0ff' : '#e0f2fe'
              }}>
                <span style={{ color: '#00f0ff', opacity: 0.6, userSelect: 'none' }}>❯</span>
                <span>{line}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};
