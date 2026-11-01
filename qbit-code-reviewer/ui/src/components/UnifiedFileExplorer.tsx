import React, { useState, useEffect } from 'react';
import { 
  Folder, 
  FolderOpen, 
  FileCode, 
  ChevronRight, 
  ChevronDown, 
  Shield, 
  AlertCircle, 
  CheckCircle2, 
  Search,
  Scan,
  Zap,
  Target
} from 'lucide-react';

interface FileTreeItem {
  name: string;
  path: string;
  type: 'directory' | 'file';
  fastEta?: string;
  fullEta?: string;
  fastDurationSec?: number;
}

interface Finding {
  id: string;
  path: string;
  start_line: number;
  end_line: number;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'fixing' | 'fixed' | 'ignored';
  content: string;
  existing_code?: string;
  suggestion_code?: string;
  cwe_id?: string;
  cve_id?: string;
}

interface UnifiedFileExplorerProps {
  currentScope: string;
  onSelectScope: (path: string) => void;
  onSelectFinding: (finding: Finding) => void;
  findings: Finding[];
  activeScanPath?: string;
  isScanning?: boolean;
  onRunScan: (path: string) => void;
  onRunFastScan: (path: string) => void;
  onRunSuperFastScan: (path: string) => void;
  superFastHours: number;
  onSuperFastHoursChange: (hours: number) => void;
}

export function UnifiedFileExplorer({
  currentScope,
  onSelectScope,
  onSelectFinding,
  findings,
  activeScanPath,
  isScanning,
  onRunScan,
  onRunFastScan,
  onRunSuperFastScan,
  superFastHours,
  onSuperFastHoursChange
}: UnifiedFileExplorerProps) {
  const [expandedDirs, setExpandedDirs] = useState<Record<string, boolean>>({});
  const [dirChildren, setDirChildren] = useState<Record<string, FileTreeItem[]>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<FileTreeItem[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [scopeEstimate, setScopeEstimate] = useState<any>(null);

  // Fetch precomputed time estimates whenever currentScope changes
  useEffect(() => {
    fetch(`/api/estimates?path=${encodeURIComponent(currentScope || '')}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) setScopeEstimate(data);
      })
      .catch(() => {});
  }, [currentScope]);

  // Group findings count by file path and by directory prefix
  const findingsByFile = React.useMemo(() => {
    const map: Record<string, Finding[]> = {};
    for (const f of findings) {
      const p = (f.path || '').replace(/\\/g, '/');
      if (!map[p]) map[p] = [];
      map[p].push(f);
    }
    return map;
  }, [findings]);

  const countDefectsUnderDir = (dirPath: string): number => {
    if (!dirPath) return findings.length;
    const norm = dirPath.replace(/\\/g, '/').replace(/\/+$/, '') + '/';
    let count = 0;
    for (const f of findings) {
      const p = (f.path || '').replace(/\\/g, '/');
      if (p.startsWith(norm) || p === dirPath) {
        count++;
      }
    }
    return count;
  };

  // Load directory items from backend
  const loadDirectory = async (dirPath: string) => {
    try {
      const res = await fetch(`/api/files?dir=${encodeURIComponent(dirPath)}`);
      if (res.ok) {
        const data = await res.json();
        setDirChildren(prev => ({
          ...prev,
          [dirPath]: data.items || []
        }));
      }
    } catch (err) {
      console.error('Failed to load directory:', err);
    }
  };

  // Initial load of root directory
  useEffect(() => {
    loadDirectory('');
  }, []);

  // Handle directory expansion
  const toggleDir = (dirPath: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const willExpand = !expandedDirs[dirPath];
    setExpandedDirs(prev => ({
      ...prev,
      [dirPath]: willExpand
    }));
    if (willExpand && !dirChildren[dirPath]) {
      loadDirectory(dirPath);
    }
  };

  // Search debouncing
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }
    const t = setTimeout(async () => {
      setSearchLoading(true);
      try {
        const res = await fetch(`/api/files?q=${encodeURIComponent(searchQuery.trim())}`);
        if (res.ok) {
          const data = await res.json();
          setSearchResults(data.results || []);
        }
      } catch {}
      setSearchLoading(false);
    }, 250);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Check status of a path: 'scanning', 'scanned', or 'unscanned'
  const getPathStatus = (itemPath: string) => {
    if (isScanning && activeScanPath) {
      if (activeScanPath === itemPath || activeScanPath.startsWith(itemPath + '/') || itemPath.startsWith(activeScanPath + '/')) {
        return 'scanning';
      }
    }
    const defectCount = countDefectsUnderDir(itemPath);
    if (defectCount > 0) return 'scanned';
    return 'unscanned';
  };

  const renderTreeItem = (item: FileTreeItem, depth = 0) => {
    const isDir = item.type === 'directory';
    const isExpanded = !!expandedDirs[item.path];
    const isSelected = currentScope === item.path;
    const status = getPathStatus(item.path);
    const defectCount = isDir ? countDefectsUnderDir(item.path) : (findingsByFile[item.path]?.length || 0);
    const children = dirChildren[item.path] || [];

    return (
      <div key={item.path} style={{ display: 'flex', flexDirection: 'column' }}>
        <div
          onClick={() => {
            onSelectScope(item.path);
            if (isDir) {
              toggleDir(item.path);
            } else if (findingsByFile[item.path] && findingsByFile[item.path].length > 0) {
              onSelectFinding(findingsByFile[item.path][0]);
            }
          }}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '5px 8px',
            paddingLeft: `${depth * 14 + 8}px`,
            borderRadius: '4px',
            cursor: 'pointer',
            background: isSelected 
              ? 'rgba(0, 240, 255, 0.18)' 
              : (status === 'scanning' ? 'rgba(0, 112, 243, 0.15)' : 'transparent'),
            borderLeft: isSelected ? '2px solid #00f0ff' : '2px solid transparent',
            color: isSelected ? '#ffffff' : (defectCount > 0 ? '#e0f2fe' : '#94a3b8'),
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.74rem',
            userSelect: 'none',
            transition: 'all 0.15s ease'
          }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0, overflow: 'hidden' }}>
            {isDir ? (
              <span 
                onClick={(e) => toggleDir(item.path, e)}
                style={{ display: 'inline-flex', alignItems: 'center', color: '#64748b', cursor: 'pointer' }}>
                {isExpanded ? <ChevronDown size={13} color="#00f0ff" /> : <ChevronRight size={13} />}
              </span>
            ) : (
              <span style={{ width: '13px' }} />
            )}

            {isDir ? (
              isExpanded ? <FolderOpen size={14} color="#00f0ff" /> : <Folder size={14} color="#38bdf8" />
            ) : (
              <FileCode size={13} color={defectCount > 0 ? '#f87171' : '#64748b'} />
            )}

            <span style={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              fontWeight: isSelected || defectCount > 0 ? 600 : 400
            }}>
              {item.name}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
            {/* Inline Precomputed Scan Time Badge */}
            {item.fastEta && status !== 'scanning' && (
              <span style={{
                fontSize: '0.62rem',
                padding: '1px 5px',
                borderRadius: '3px',
                background: 'rgba(255, 184, 0, 0.08)',
                border: '1px solid rgba(255, 184, 0, 0.25)',
                color: '#fbbf24',
                fontFamily: '"JetBrains Mono", monospace'
              }} title={`Estimated FastScan time: ${item.fastEta} (Full: ${item.fullEta})`}>
                ⚡ {item.fastEta}
              </span>
            )}

            {status === 'scanning' && (
              <span style={{
                fontSize: '0.62rem',
                padding: '1px 5px',
                borderRadius: '3px',
                background: 'rgba(0, 112, 243, 0.3)',
                border: '1px solid #00f0ff',
                color: '#00f0ff',
                fontFamily: 'Orbitron, sans-serif'
              }} className="animate-pulse">
                SCANNING...
              </span>
            )}

            {defectCount > 0 && (
              <span style={{
                fontSize: '0.62rem',
                fontWeight: 700,
                padding: '1px 5px',
                borderRadius: '3px',
                background: 'rgba(239, 68, 68, 0.2)',
                border: '1px solid rgba(239, 68, 68, 0.5)',
                color: '#f87171',
                fontFamily: 'Orbitron, sans-serif'
              }}>
                {defectCount}
              </span>
            )}
          </div>
        </div>

        {/* Nested Directory Indented Children */}
        {isDir && isExpanded && (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {children.length === 0 ? (
              <div style={{ paddingLeft: `${(depth + 1) * 14 + 8}px`, padding: '3px 0', color: '#475569', fontSize: '0.7rem' }}>
                (empty folder)
              </div>
            ) : (
              children.map(child => renderTreeItem(child, depth + 1))
            )}
          </div>
        )}
      </div>
    );
  };

  const isScopeUnscanned = currentScope ? countDefectsUnderDir(currentScope) === 0 : false;

  return (
    <div style={{
      background: '#020612',
      border: '1px solid rgba(0, 240, 255, 0.25)',
      borderRadius: '8px',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 220px)',
      position: 'sticky',
      top: '85px',
      boxShadow: '0 0 20px rgba(0, 240, 255, 0.1)'
    }}>
      {/* HEADER: VS CODE STYLE TITLE BAR */}
      <div style={{
        padding: '10px 14px',
        background: 'rgba(0, 240, 255, 0.08)',
        borderBottom: '1px solid rgba(0, 240, 255, 0.15)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FolderOpen size={15} color="#00f0ff" />
          <span style={{ fontSize: '0.78rem', fontWeight: 800, fontFamily: 'Orbitron, sans-serif', color: '#ffffff', letterSpacing: '0.5px' }}>
            WORKSPACE EXPLORER
          </span>
        </div>
        <span style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: '"JetBrains Mono", monospace' }}>
          {findings.length} Defects
        </span>
      </div>

      {/* QUICK SEARCH FILTER */}
      <div style={{ padding: '8px 10px', borderBottom: '1px solid rgba(0, 240, 255, 0.1)' }}>
        <div style={{ position: 'relative' }}>
          <Search size={12} style={{ position: 'absolute', left: '8px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
          <input
            type="text"
            placeholder="Filter files / folders..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 8px 6px 26px',
              borderRadius: '4px',
              background: 'rgba(0, 0, 0, 0.6)',
              border: '1px solid rgba(0, 240, 255, 0.2)',
              color: '#fff',
              fontSize: '0.72rem',
              fontFamily: '"JetBrains Mono", monospace'
            }}
          />
        </div>
      </div>

      {/* TREE VIEW SCROLL AREA */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '6px 4px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {/* Workspace Root Item */}
        <div
          onClick={() => onSelectScope('')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '6px 8px',
            borderRadius: '4px',
            cursor: 'pointer',
            background: currentScope === '' ? 'rgba(0, 240, 255, 0.18)' : 'transparent',
            borderLeft: currentScope === '' ? '2px solid #00f0ff' : '2px solid transparent',
            color: currentScope === '' ? '#00f0ff' : '#94a3b8',
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.75rem',
            fontWeight: currentScope === '' ? 700 : 500
          }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Target size={13} color="#00f0ff" />
            <span>Entire Workspace (Root)</span>
          </div>
          <span style={{ fontSize: '0.64rem', padding: '1px 5px', borderRadius: '3px', background: 'rgba(0, 240, 255, 0.12)', color: '#38bdf8' }}>
            {findings.length}
          </span>
        </div>

        {/* Render Search Results or Directory Tree */}
        {searchQuery.trim() ? (
          searchLoading ? (
            <div style={{ padding: '12px', textAlign: 'center', color: '#64748b', fontSize: '0.74rem' }}>Searching...</div>
          ) : searchResults.length === 0 ? (
            <div style={{ padding: '12px', textAlign: 'center', color: '#64748b', fontSize: '0.74rem' }}>No matching items</div>
          ) : (
            searchResults.map(item => renderTreeItem(item, 0))
          )
        ) : (
          (dirChildren[''] || []).map(item => renderTreeItem(item, 0))
        )}
      </div>

      {/* ACTION DOCK: CONTEXT-AWARE SCAN TRIGGER BUTTONS */}
      <div style={{
        padding: '10px',
        borderTop: '1px solid rgba(0, 240, 255, 0.2)',
        background: '#010309',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.68rem', color: '#64748b', fontFamily: '"JetBrains Mono", monospace' }}>
          <span>TARGET: <strong style={{ color: currentScope ? '#00f0ff' : '#94a3b8' }}>{currentScope || 'Entire Workspace'}</strong></span>
          {isScopeUnscanned && <span style={{ color: '#fbbf24', fontWeight: 700 }}>UNSCANNED</span>}
        </div>

        {/* Target Precomputed Scan Duration Summary Card */}
        {scopeEstimate && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '4px 8px',
            borderRadius: '5px',
            background: 'rgba(0, 240, 255, 0.05)',
            border: '1px solid rgba(0, 240, 255, 0.15)',
            fontSize: '0.68rem',
            fontFamily: '"JetBrains Mono", monospace'
          }}>
            <span style={{ color: '#94a3b8' }}>Est. FastScan:</span>
            <span style={{ color: '#fbbf24', fontWeight: 700 }}>⚡ {scopeEstimate.fastEtaFormatted || '~1m'}</span>
            <span style={{ color: '#64748b' }}>|</span>
            <span style={{ color: '#94a3b8' }}>Full:</span>
            <span style={{ color: '#38bdf8', fontWeight: 700 }}>🔍 {scopeEstimate.fullEtaFormatted || '~3m'}</span>
          </div>
        )}

        {/* SuperFast Threshold Controller */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          borderRadius: '5px',
          padding: '4px 8px',
          marginBottom: '8px'
        }}>
          <span style={{ fontSize: '0.66rem', color: '#34d399', fontFamily: 'Orbitron, sans-serif', fontWeight: 600 }}>
            SUPER LIMIT:
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <input
              type="number"
              min="0.5"
              max="24"
              step="0.5"
              value={superFastHours}
              onChange={(e) => onSuperFastHoursChange(Math.max(0.1, parseFloat(e.target.value) || 1.0))}
              style={{
                width: '46px',
                padding: '2px 4px',
                background: '#020612',
                border: '1px solid rgba(16, 185, 129, 0.5)',
                borderRadius: '4px',
                color: '#34d399',
                fontSize: '0.72rem',
                fontFamily: '"JetBrains Mono", monospace',
                textAlign: 'center',
                fontWeight: 700
              }}
            />
            <span style={{ fontSize: '0.66rem', color: '#94a3b8', fontFamily: 'Orbitron, sans-serif' }}>HRS</span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '6px' }}>
          {/* FastScan */}
          <button
            onClick={() => onRunFastScan(currentScope)}
            disabled={isScanning}
            title="FastScan: Exclude non-code & tests"
            style={{
              padding: '7px 4px',
              borderRadius: '5px',
              border: isScopeUnscanned ? '1px solid #ffb800' : '1px solid rgba(255, 184, 0, 0.4)',
              background: isScopeUnscanned ? 'linear-gradient(135deg, rgba(255, 184, 0, 0.35), rgba(255, 85, 0, 0.4))' : 'rgba(255, 184, 0, 0.1)',
              color: '#ffb800',
              fontWeight: 800,
              fontSize: '0.68rem',
              fontFamily: 'Orbitron, sans-serif',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '4px',
              boxShadow: isScopeUnscanned ? '0 0 12px rgba(255, 184, 0, 0.4)' : 'none'
            }}>
            <Zap size={11} />
            FAST
          </button>

          {/* SuperFast Scan (Custom Hour Budget Pruning) */}
          <button
            onClick={() => onRunSuperFastScan(currentScope)}
            disabled={isScanning}
            title={`SuperFast Scan: Guarantees scan under ${superFastHours}h by auto-pruning heaviest modules`}
            style={{
              padding: '7px 4px',
              borderRadius: '5px',
              border: isScopeUnscanned ? '1px solid #10b981' : '1px solid rgba(16, 185, 129, 0.4)',
              background: isScopeUnscanned ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.35), rgba(5, 150, 105, 0.4))' : 'rgba(16, 185, 129, 0.1)',
              color: '#34d399',
              fontWeight: 800,
              fontSize: '0.68rem',
              fontFamily: 'Orbitron, sans-serif',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '4px',
              boxShadow: isScopeUnscanned ? '0 0 12px rgba(16, 185, 129, 0.4)' : 'none'
            }}>
            <Zap size={11} color="#34d399" />
            SUPER &lt;{superFastHours}H
          </button>

          {/* Full Scan */}
          <button
            onClick={() => onRunScan(currentScope)}
            disabled={isScanning}
            title="Full Deep AI Scan"
            style={{
              padding: '7px 4px',
              borderRadius: '5px',
              border: 'none',
              background: isScopeUnscanned ? 'linear-gradient(135deg, #0070f3, #00f0ff)' : 'rgba(0, 112, 243, 0.25)',
              color: isScopeUnscanned ? '#000' : '#00f0ff',
              fontWeight: 800,
              fontSize: '0.68rem',
              fontFamily: 'Orbitron, sans-serif',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '4px',
              boxShadow: isScopeUnscanned ? '0 0 12px rgba(0, 240, 255, 0.5)' : 'none'
            }}>
            <Scan size={11} />
            SCAN
          </button>
        </div>
      </div>
    </div>
  );
}
