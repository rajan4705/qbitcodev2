import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  AlertCircle, 
  CheckCircle2, 
  MessageSquare, 
  Zap, 
  Search, 
  X, 
  RefreshCw, 
  Send, 
  Code2,
  Download,
  FolderGit2,
  Folder,
  FolderOpen,
  FileCode,
  Terminal,
  ChevronDown,
  ChevronRight,
  Radio,
  Copy,
  Check,
  FileSpreadsheet,
  Split,
  Layers,
  Package
} from 'lucide-react';
import { MatrixRain } from './components/MatrixRain';
import { CyberTerminalTabs } from './components/CyberTerminalTabs';
import { TargetScopeExplorer } from './components/TargetScopeExplorer';
import { UnifiedFileExplorer } from './components/UnifiedFileExplorer';

interface Finding {
  id: string;
  path: string;
  start_line: number;
  end_line: number;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  content: string;
  existing_code?: string;
  suggestion_code?: string;
  patch_description?: string;
  cwe_id?: string;
  cwe_title?: string;
  cve_id?: string;
  ref_cwe_id?: string;
  ref_cve_id?: string;
  source?: string;
  nvd_severity?: string;
  status: 'open' | 'fixing' | 'fixed' | 'ignored';
}

interface ServerStatus {
  workspace: string;
  vllm: {
    url: string;
    model: string;
    healthy: boolean;
  };
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface ScaVulnerability {
  cve_id: string;
  advisory_id?: string;
  severity: string;
  cwe?: string;
  title: string;
  fixed_in?: string;
}

interface ScaPackageRisk {
  package: string;
  installed_version: string;
  ecosystem: string;
  highest_severity: string;
  recommended_fix?: string;
  manifest_file?: string;
  cve_summary?: string[];
  vulnerabilities?: ScaVulnerability[];
  code_usage?: {
    status: string;
    is_imported: boolean;
    import_count: number;
    traces?: Array<{ file: string; line: number; snippet: string }>;
  };
}

interface ScaReport {
  repo_name?: string;
  repo_path?: string;
  summary?: {
    total_packages: number;
    clean_packages: number;
    vulnerable_packages: number;
    actionable_active_risks: number;
    dormant_manifest_risks: number;
    severity_breakdown: Record<string, number>;
  };
  manifest_files?: Record<string, number>;
  actionable_risks?: ScaPackageRisk[];
  dormant_risks?: ScaPackageRisk[];
}

export default function App() {
  const [mainView, setMainView] = useState<'code' | 'packages'>('code');
  const [scaReport, setScaReport] = useState<ScaReport | null>(null);
  const [scaLoading, setScaLoading] = useState(false);
  const [scaError, setScaError] = useState<string | null>(null);
  const [expandedScaPkgs, setExpandedScaPkgs] = useState<Record<string, boolean>>({});
  const [findings, setFindings] = useState<Finding[]>([]);
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeFilter, setActiveFilter] = useState<'all' | 'critical-high' | 'security' | 'open' | 'fixed'>('critical-high');
  const [minSeverityFilter, setMinSeverityFilter] = useState<'high' | 'all'>('high');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportMode, setExportMode] = useState<'with_patches' | 'without_patches' | 'patches_only'>('with_patches');
  const [exportScope, setExportScope] = useState<'consolidated' | 'by_repository'>('consolidated');
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);
  const [cardViewModes, setCardViewModes] = useState<Record<string, 'stacked' | 'diff'>>({});
  const [groupByDir, setGroupByDir] = useState(true);
  const [expandedDirs, setExpandedDirs] = useState<Record<string, boolean>>({});
  const [synthesizing, setSynthesizing] = useState(false);
  const [synthesisProgress, setSynthesisProgress] = useState<{
    current: number;
    total: number;
    percent: number;
    currentPath: string;
    currentLine: number;
    currentCategory: string;
    statusText: string;
    completed: boolean;
  }>({
    current: 0,
    total: 0,
    percent: 0,
    currentPath: '',
    currentLine: 0,
    currentCategory: '',
    statusText: '',
    completed: false
  });

  // FastScan state
  const [fastScanOpen, setFastScanOpen] = useState(false);
  const [fastScanLoading, setFastScanLoading] = useState(false);
  const [fastScanData, setFastScanData] = useState<any>(null);
  const [fastScanTab, setFastScanTab] = useState<'folders' | 'files'>('folders');
  const [superFastHours, setSuperFastHours] = useState<number>(5.0);
  const [workspaceEstimate, setWorkspaceEstimate] = useState<any>(null);

  // Poll precomputed workspace estimation
  useEffect(() => {
    const fetchEstimates = () => {
      fetch('/api/estimates?path=')
        .then(res => res.ok ? res.json() : null)
        .then(data => {
          if (data) setWorkspaceEstimate(data);
        })
        .catch(() => {});
    };
    fetchEstimates();
    const interval = setInterval(fetchEstimates, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleDirectFastScan = async (targetOverride?: string) => {
    const target = (targetOverride !== undefined ? targetOverride : scanPath) || '';
    setScanPath(target);
    // 1. Kick off fastscan exemptions discovery asynchronously in background
    fetch('/api/fastscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: target })
    }).catch(() => {});
    // 2. Immediately launch the scan without waiting or showing the modal
    handleRunScan(target);
  };

  const handleDirectSuperFastScan = async (targetOverride?: string) => {
    const target = (targetOverride !== undefined ? targetOverride : scanPath) || '';
    setScanPath(target);
    // 1. Kick off superfast budget optimization asynchronously in background with customizable hours
    fetch('/api/superfastscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: target, maxHours: superFastHours })
    }).catch(() => {});
    // 2. Immediately launch the scan without waiting or showing the modal
    handleRunScan(target);
  };

  const handleOpenFastScan = async (targetOverride?: string) => {
    const target = (targetOverride !== undefined ? targetOverride : scanPath) || '';
    setFastScanOpen(true);
    setFastScanLoading(true);
    try {
      const res = await fetch('/api/fastscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: target })
      });
      if (res.ok) {
        const data = await res.json();
        setFastScanData(data);
      }
    } catch (e) {
      console.error('Failed to run fastscan:', e);
    } finally {
      setFastScanLoading(false);
    }
  };

  const handleOpenSuperFastScan = async (targetOverride?: string) => {
    const target = (targetOverride !== undefined ? targetOverride : scanPath) || '';
    setFastScanOpen(true);
    setFastScanLoading(true);
    try {
      const res = await fetch('/api/superfastscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: target, maxHours: 5.0 })
      });
      if (res.ok) {
        const data = await res.json();
        setFastScanData(data);
      }
    } catch (e) {
      console.error('Failed to run superfastscan:', e);
    } finally {
      setFastScanLoading(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(id);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  // Typewriter effect for header
  const [titleText, setTitleText] = useState('');
  const fullTitle = 'QBIT CODE REVIEWER';

  useEffect(() => {
    let idx = 0;
    const timer = setInterval(() => {
      setTitleText(fullTitle.slice(0, idx + 1));
      idx++;
      if (idx >= fullTitle.length) clearInterval(timer);
    }, 60);
    return () => clearInterval(timer);
  }, []);

  // Multi-engine terminal logs
  const [logs, setLogs] = useState<{
    vllm: string[];
    scan: string[];
    fix: string[];
    cve8080: string[];
    sca8082: string[];
  }>({
    vllm: [
      '[vLLM H100] Model weights loaded: qwen3-coder-30b-a3b-instruct',
      '[vLLM H100] Context window: 65,536 tokens | YaRN RoPE dynamic scaling active',
      '[vLLM H100] Listening on 127.0.0.1:8000/v1'
    ],
    scan: [
      '[ENGINE] Scanning pipeline initialized.',
      '[ENGINE] Max prompt ceiling: 28,672 tokens | Completion limit: 4,096 tokens',
      '[ENGINE] Standby for security audit dispatch...'
    ],
    fix: [
      '[REMEDIATION] Autonomous patch engine armed.',
      '[REMEDIATION] Direct AST/diff replacement ready.'
    ],
    cve8080: [
      '[CVE/CWE ENRICHER :8080] Vector database service monitoring active.',
      '[CVE/CWE ENRICHER :8080] Background non-blocking enrichment workers online (timeout: 1.5s).'
    ],
    sca8082: [
      '[SCA ENGINE :8082] Universal dependency analyzer ready on 0.0.0.0:8082.',
      '[SCA ENGINE :8082] Automated lockfile & manifest security checker armed.'
    ]
  });

  // Chat state (Strict Read-Only Vulnerability Advisor)
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: 'SYSTEM ACTIVE [READ-ONLY AUDIT MODE]. I am Qbit AI, your vulnerability explainer copilot. Select "DISCUSS IN CHAT" on any finding or ask questions to understand security risks, attack vectors, and CWE classifications without mutating files on disk.'
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const [metrics, setMetrics] = useState<any>(null);

  useEffect(() => {
    fetchStatus();
    fetchFindings();
    fetchVllmLogs();
    fetchMetrics();
    fetchScaReport();
    checkActiveScan();

    const interval = setInterval(() => {
      fetchFindings();
      fetchMetrics();
      fetchVllmLogs();
      checkActiveScan();
    }, 2500);

    return () => clearInterval(interval);
  }, []);

  const activeStreamAttachedRef = useRef(false);

  const checkActiveScan = async () => {
    if (activeStreamAttachedRef.current) return;
    try {
      const res = await fetch('/api/scan/active');
      if (!res.ok) return;
      const data = await res.json();
      if (data.active && data.status === 'running') {
        attachToScanStream(data.jobId);
      }
    } catch {}
  };

  const attachToScanStream = (jobId?: string) => {
    if (activeStreamAttachedRef.current) return;
    activeStreamAttachedRef.current = true;
    setLoading(true);
    setTerminalOpen(true);

    const streamUrl = jobId ? `/api/scan/stream/${jobId}` : '/api/scan/stream';
    const es = new EventSource(streamUrl);

    es.addEventListener('status', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.filesTotal) {
          setScanProgress(p => ({
            ...p,
            totalFiles: payload.filesTotal,
            reviewedFiles: payload.filesReviewed || 0,
            percent: payload.filesTotal > 0 ? Math.round(((payload.filesReviewed || 0) / payload.filesTotal) * 100) : 0
          }));
        }
      } catch {}
    });

    es.addEventListener('log', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.message) {
          const msg = payload.message;
          setLogs(prev => ({
            ...prev,
            scan: [...prev.scan, msg]
          }));

          const reviewMatch = msg.match(/reviewing (\d+) in/) || msg.match(/(\d+) file\(s\) discovered/);
          if (reviewMatch) {
            const count = parseInt(reviewMatch[1], 10);
            setScanProgress(p => {
              const actualTotal = Math.max(p.totalFiles, count);
              return {
                ...p,
                totalFiles: actualTotal,
                percent: actualTotal > 0 && p.reviewedFiles > 0 ? Math.min(99, Math.round((p.reviewedFiles / actualTotal) * 100)) : p.percent
              };
            });
          }
        }
      } catch {}
    });

    es.addEventListener('progress', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        setScanProgress(p => {
          const reviewed = payload.reviewedFiles !== undefined ? payload.reviewedFiles : p.reviewedFiles;
          const skipped = payload.skippedFiles !== undefined ? payload.skippedFiles : p.skippedFiles;
          const total = payload.totalFiles !== undefined ? Math.max(p.totalFiles, payload.totalFiles) : p.totalFiles;
          const pct = payload.percent !== undefined ? payload.percent : (total > 0 ? Math.min(99, Math.round(((reviewed + skipped) / total) * 100)) : p.percent);
          return {
            ...p,
            reviewedFiles: reviewed,
            skippedFiles: skipped,
            totalFiles: total,
            percent: pct,
            etaFormatted: payload.etaFormatted || p.etaFormatted,
            currentSubrepo: payload.currentSubrepo || payload.subrepo || p.currentSubrepo,
            subrepoIndex: payload.subrepoIndex !== undefined ? payload.subrepoIndex : p.subrepoIndex,
            totalSubrepos: payload.totalSubrepos !== undefined ? payload.totalSubrepos : p.totalSubrepos,
            completedSubrepos: payload.completedSubrepos !== undefined ? payload.completedSubrepos : p.completedSubrepos,
            subrepoEtaFormatted: payload.subrepoEtaFormatted || p.subrepoEtaFormatted,
            overallEtaFormatted: payload.overallEtaFormatted || p.overallEtaFormatted
          };
        });
      } catch {}
    });

    es.addEventListener('finding', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.finding) {
          setFindings(prev => {
            if (prev.some(f => f.id === payload.finding.id)) return prev;
            return [payload.finding, ...prev];
          });
        }
      } catch {}
    });

    es.addEventListener('complete', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.findings) {
          setFindings(payload.findings);
        }
      } catch {}
      setScanProgress(p => ({ ...p, percent: 100 }));
      setLoading(false);
      activeStreamAttachedRef.current = false;
      es.close();
    });

    es.addEventListener('interrupted', (e: any) => {
      setLoading(false);
      activeStreamAttachedRef.current = false;
      es.close();
    });

    es.addEventListener('error', () => {
      setLoading(false);
      activeStreamAttachedRef.current = false;
      es.close();
    });
  };

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch {}
  };

  const fetchFindings = async () => {
    try {
      const res = await fetch('/api/findings');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.findings)) {
          setFindings(prev => {
            // When actively scanning, preserve streaming findings so polling doesn't overwrite with a smaller list
            if (loading && prev.length > (data.findings.length || 0)) {
              return prev;
            }
            return data.findings;
          });
        }
      }
    } catch {}
  };

  const fetchScaReport = async (customPath?: string) => {
    setScaLoading(true);
    setScaError(null);
    try {
      let data: ScaReport | null = null;
      let errMessage = '';

      // Primary strategy: Call server proxy /api/sca/scan
      try {
        const res = await fetch('/api/sca/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_path: customPath || scanPath || undefined,
            min_severity: 'LOW',
            active_only: false
          })
        });
        if (res.ok) {
          data = await res.json();
        } else {
          const errJson = await res.json().catch(() => ({}));
          errMessage = errJson.error || `HTTP ${res.status}`;
        }
      } catch (err: any) {
        errMessage = err.message;
      }

      // Secondary strategy: Direct port 8082 connection fallback
      if (!data) {
        try {
          const resDirect = await fetch('http://localhost:8082/api/v1/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              target_path: customPath || scanPath || '/app',
              min_severity: 'LOW',
              active_only: false
            })
          });
          if (resDirect.ok) {
            data = await resDirect.json();
          }
        } catch {}
      }

      if (data) {
        setScaReport(data);
      } else {
        throw new Error(errMessage || 'Failed to scan packages via SCA API (port 8082)');
      }
    } catch (err: any) {
      setScaError(err.message || 'Failed to scan packages via SCA API (port 8082)');
    } finally {
      setScaLoading(false);
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch {}
  };

  const fetchVllmLogs = async () => {
    try {
      const res = await fetch('/api/vllm/logs');
      if (res.ok) {
        const data = await res.json();
        if (data.lines && data.lines.length > 0) {
          setLogs(prev => ({
            ...prev,
            vllm: data.lines
          }));
        }
      }
    } catch {}
  };

  const [scanPath, setScanPath] = useState('');
  const [switchingModel, setSwitchingModel] = useState<boolean>(false);
  const [activeModelVariant, setActiveModelVariant] = useState<string>('30b');
  const [availableModels, setAvailableModels] = useState<any[]>([]);

  const fetchVllmModels = async () => {
    try {
      const res = await fetch('/api/vllm/models');
      if (res.ok) {
        const data = await res.json();
        if (data.activeModelId) {
          setActiveModelVariant(data.activeModelId);
        }
        if (Array.isArray(data.models)) {
          setAvailableModels(data.models);
        }
      }
    } catch {}
  };

  const handleSwitchModel = async (targetVariant: string) => {
    if (switchingModel || targetVariant === activeModelVariant) return;
    setSwitchingModel(true);
    setLogs(prev => ({
      ...prev,
      vllm: [
        ...prev.vllm,
        `[${new Date().toLocaleTimeString()}] ⚡ Initiating switch to ${targetVariant.toUpperCase()} model on vLLM...`,
        `[${new Date().toLocaleTimeString()}] Stopping previous server, clearing GPU VRAM, and warming up engine...`
      ]
    }));
    try {
      const res = await fetch('/api/vllm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ variant: targetVariant })
      });
      if (res.ok) {
        const data = await res.json();
        setActiveModelVariant(data.activeModelId || targetVariant);
        fetchStatus();
        fetch('/api/estimates?path=')
          .then(r => r.ok ? r.json() : null)
          .then(est => { if (est) setWorkspaceEstimate(est); })
          .catch(() => {});
        setLogs(prev => ({
          ...prev,
          vllm: [
            ...prev.vllm,
            `[${new Date().toLocaleTimeString()}] ✔ vLLM successfully switched to ${targetVariant.toUpperCase()}! Concurrency set to ${data.concurrency} workers.`,
            `[${new Date().toLocaleTimeString()}] ⚡ Recalculated FastScan and FullScan ETAs with ${data.concurrency}x parallel workers.`
          ]
        }));
      } else {
        const errJson = await res.json().catch(() => ({}));
        alert(`Failed to switch model: ${errJson.error || 'Server error'}`);
      }
    } catch (err: any) {
      alert(`Network error switching model: ${err.message}`);
    } finally {
      setSwitchingModel(false);
    }
  };

  useEffect(() => {
    fetchVllmModels();
  }, []);
  const [scanProgress, setScanProgress] = useState<{
    totalFiles: number;
    reviewedFiles: number;
    skippedFiles: number;
    estimatedTokens: string;
    percent: number;
    etaFormatted: string;
    startTime: number | null;
    currentSubrepo?: string;
    subrepoIndex?: number;
    totalSubrepos?: number;
    completedSubrepos?: number;
    subrepoEtaFormatted?: string;
    overallEtaFormatted?: string;
  }>({
    totalFiles: 0,
    reviewedFiles: 0,
    skippedFiles: 0,
    estimatedTokens: '',
    percent: 0,
    etaFormatted: '',
    startTime: null,
    currentSubrepo: '',
    subrepoIndex: 0,
    totalSubrepos: 0,
    completedSubrepos: 0,
    subrepoEtaFormatted: '',
    overallEtaFormatted: ''
  });

  const [groupByFolder, setGroupByFolder] = useState<boolean>(true);
  const [collapsedFolders, setCollapsedFolders] = useState<Record<string, boolean>>({});

  const [selectedTreePath, setSelectedTreePath] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const toggleFolderCollapse = (folderPath: string) => {
    setCollapsedFolders(prev => ({
      ...prev,
      [folderPath]: !prev[folderPath]
    }));
  };

  const collapseAllFolders = (folders: string[]) => {
    const map: Record<string, boolean> = {};
    for (const f of folders) map[f] = true;
    setCollapsedFolders(map);
  };

  const expandAllFolders = () => {
    setCollapsedFolders({});
  };

  const handleRunScan = async (overridePath?: string) => {
    const targetScope = (overridePath !== undefined ? overridePath : scanPath).trim();
    if (overridePath !== undefined) {
      setScanPath(overridePath);
    }

    setLoading(true);
    setTerminalOpen(true);
    setFindings([]); // Reset findings so they stream in real-time
    setScanProgress({ totalFiles: 0, reviewedFiles: 0, skippedFiles: 0, estimatedTokens: '', percent: 0, etaFormatted: '', startTime: Date.now() });

    const activeWorkers = activeModelVariant === '14b' ? 8 : 4;
    const activeModelName = activeModelVariant === '14b' ? 'Qwen2.5-Coder-14B' : (activeModelVariant === '7b' ? 'Qwen2.5-Coder-7B' : 'Qwen3-Coder-30B');

    setLogs(prev => ({
      ...prev,
      scan: [
        `[${new Date().toLocaleTimeString()}] 🚀 DISPATCHING QBIT VULNERABILITY SCAN ENGINE...`,
        `[${new Date().toLocaleTimeString()}] Target Scope: ${targetScope ? targetScope : 'Entire Workspace (Full Scan)'}`,
        `[${new Date().toLocaleTimeString()}] 🎯 Severity Policy: ${minSeverityFilter === 'high' ? 'HIGH & CRITICAL ONLY (Noise filtered)' : 'ALL SEVERITIES'}`,
        `[${new Date().toLocaleTimeString()}] 🔍 Initializing AST graph & discovering sub-repositories...`,
        `[${new Date().toLocaleTimeString()}] ⚡ Computing upfront SHA-256 content hashes for instant cross-stack deduplication...`,
        `[${new Date().toLocaleTimeString()}] 🛡️ Concurrency: ${activeWorkers} parallel AI inspection workers (${activeModelName})`
      ]
    }));

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          pathFilter: targetScope,
          minSeverity: minSeverityFilter
        })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const payload = JSON.parse(line.slice(6));

                // Process log messages and extract progress/ETA
                if (payload.message) {
                  const msg = payload.message;
                  setLogs(prev => ({
                    ...prev,
                    scan: [...prev.scan, msg]
                  }));

                  // Regex parse file count: reviewing X in ... (retain highest count)
                  const reviewMatch = msg.match(/reviewing (\d+) in/) || msg.match(/(\d+) file\(s\) discovered/);
                  if (reviewMatch) {
                    const count = parseInt(reviewMatch[1], 10);
                    setScanProgress(p => {
                      const actualTotal = Math.max(p.totalFiles, count);
                      return {
                        ...p,
                        totalFiles: actualTotal,
                        percent: actualTotal > 0 && p.reviewedFiles > 0 ? Math.min(99, Math.round((p.reviewedFiles / actualTotal) * 100)) : p.percent
                      };
                    });
                  }

                  // Regex parse estimated cost / tokens
                  const estMatch = msg.match(/est\. ([\d\.]+M?K?) input.*≈ ([\d\.]+M?K?)/);
                  if (estMatch) {
                    setScanProgress(p => ({ ...p, estimatedTokens: estMatch[2] }));
                  }
                }

                // Explicit progress payload from server (real distinct file count + ETA)
                if (payload.reviewedFiles !== undefined || payload.totalFiles !== undefined || payload.currentSubrepo || payload.completedSubrepos !== undefined) {
                  setScanProgress(p => {
                    const reviewed = payload.reviewedFiles !== undefined ? payload.reviewedFiles : p.reviewedFiles;
                    const skipped = payload.skippedFiles !== undefined ? payload.skippedFiles : p.skippedFiles;
                    const total = payload.totalFiles !== undefined ? Math.max(p.totalFiles, payload.totalFiles) : p.totalFiles;
                    const pct = payload.percent !== undefined ? payload.percent : (total > 0 ? Math.min(99, Math.round(((reviewed + skipped) / total) * 100)) : p.percent);
                    return {
                      ...p,
                      reviewedFiles: reviewed,
                      skippedFiles: skipped,
                      totalFiles: total,
                      percent: pct,
                      etaFormatted: payload.etaFormatted || p.etaFormatted,
                      currentSubrepo: payload.currentSubrepo || payload.subrepo || p.currentSubrepo,
                      subrepoIndex: payload.subrepoIndex !== undefined ? payload.subrepoIndex : p.subrepoIndex,
                      totalSubrepos: payload.totalSubrepos !== undefined ? payload.totalSubrepos : p.totalSubrepos,
                      completedSubrepos: payload.completedSubrepos !== undefined ? payload.completedSubrepos : p.completedSubrepos,
                      subrepoEtaFormatted: payload.subrepoEtaFormatted || p.subrepoEtaFormatted,
                      overallEtaFormatted: payload.overallEtaFormatted || p.overallEtaFormatted
                    };
                  });
                }

                // Live Real-Time Finding Streaming
                if (payload.finding) {
                  setFindings(prev => {
                    if (prev.some(f => f.id === payload.finding.id)) return prev;
                    return [payload.finding, ...prev];
                  });
                }

                // Final payload completion
                if (payload.findings) {
                  setFindings(payload.findings);
                  setScanProgress(p => ({ ...p, percent: 100 }));
                  setLogs(prev => ({
                    ...prev,
                    scan: [
                      ...prev.scan,
                      `[${new Date().toLocaleTimeString()}] ✔ COMPLETE: ${payload.findings.length} findings recorded in target workspace.`
                    ]
                  }));
                }
              } catch {}
            }
          }
        }
      }
    } catch (err: any) {
      setLogs(prev => ({
        ...prev,
        scan: [...prev.scan, `[${new Date().toLocaleTimeString()}] ✖ Scan exception: ${err.message}`]
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleStopScan = async () => {
    try {
      await fetch('/api/scan/stop', { method: 'POST' });
      setLoading(false);
      setLogs(prev => ({
        ...prev,
        scan: [
          ...prev.scan,
          `[${new Date().toLocaleTimeString()}] 🛑 Scan aborted by user.`
        ]
      }));
    } catch (e: any) {
      console.error('Failed to stop scan:', e);
    }
  };

  const handleRunReview = async () => {
    setLoading(true);
    setTerminalOpen(true);
    setLogs(prev => ({
      ...prev,
      scan: [
        `[${new Date().toLocaleTimeString()}] 🔎 DISPATCHING QBIT GIT DIFF REVIEW ENGINE...`
      ]
    }));

    try {
      const res = await fetch('/api/review', { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const payload = JSON.parse(line.slice(6));
                if (payload.message) {
                  setLogs(prev => ({
                    ...prev,
                    scan: [...prev.scan, payload.message]
                  }));
                }
                if (payload.findings) {
                  setFindings(payload.findings);
                  setLogs(prev => ({
                    ...prev,
                    scan: [
                      ...prev.scan,
                      `[${new Date().toLocaleTimeString()}] ✔ COMPLETE: ${payload.findings.length} review findings identified.`
                    ]
                  }));
                }
              } catch {}
            }
          }
        }
      }
    } catch (err: any) {
      setLogs(prev => ({
        ...prev,
        scan: [...prev.scan, `[${new Date().toLocaleTimeString()}] ✖ Review error: ${err.message}`]
      }));
    } finally {
      setLoading(false);
    }
  };

  const sendChatMessage = async (userText: string, findingOverride?: Finding) => {
    if (!userText.trim() || chatLoading) return;

    const targetFinding = findingOverride !== undefined ? findingOverride : selectedFinding;
    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: userText }];
    setMessages(newMessages);
    setChatLoading(true);

    setLogs(prev => ({
      ...prev,
      vllm: [
        ...prev.vllm,
        `[${new Date().toLocaleTimeString()}] Prompt dispatched to vLLM (${newMessages.length} turns)`
      ]
    }));

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newMessages,
          findingContext: targetFinding
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      let assistantText = '';
      setMessages(prev => [...prev, { role: 'assistant', content: '' }]);

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ') && line !== 'data: [DONE]') {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.token) {
                  assistantText += data.token;
                  setMessages(prev => {
                    const copy = [...prev];
                    copy[copy.length - 1] = { role: 'assistant', content: assistantText };
                    return copy;
                  });
                }
              } catch {}
            }
          }
        }
      }
    } catch (err: any) {
      setMessages(prev => [...prev, { role: 'assistant', content: `[ERROR] ${err.message}` }]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMessage.trim() || chatLoading) return;
    const text = inputMessage;
    setInputMessage('');
    await sendChatMessage(text);
  };

  const handleDiscussFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    const userPrompt = `Can you analyze the defect in ${finding.path}:${finding.start_line} (${finding.category} - ${finding.severity}), explain the exact vulnerability risk, and provide a secure, production-grade fix?`;
    sendChatMessage(userPrompt, finding);
  };

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setExportOpen(false);
  };

  const escapeCsv = (val: any): string => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const extractRepoName = (filepath: string): string => {
    const parts = (filepath || '').replace(/\\/g, '/').split('/').filter(Boolean);
    if (parts.length > 1 && (parts[0] === 'testing repos' || parts[0] === 'repos' || parts[0] === 'ps1_mock2')) {
      return parts[1];
    }
    return parts.length > 1 ? parts[0] : 'repository';
  };

  const getBenchmarkLanguage = (filepath: string): string => {
    if (!filepath) return 'C';
    const ext = filepath.split('.').pop()?.toLowerCase() || '';
    switch (ext) {
      case 'c':
      case 'h':
        return 'C';
      case 'cpp':
      case 'hpp':
      case 'cc':
      case 'cxx':
        return 'C++';
      case 'py':
        return 'Python';
      case 'js':
      case 'mjs':
      case 'cjs':
        return 'JavaScript';
      case 'ts':
      case 'tsx':
        return 'TypeScript';
      case 'java':
        return 'Java';
      case 'go':
        return 'Go';
      case 'rs':
        return 'Rust';
      case 'kt':
      case 'kts':
        return 'Kotlin';
      case 'php':
        return 'PHP';
      case 'swift':
        return 'Swift';
      case 'rb':
        return 'Ruby';
      case 'cs':
        return 'C#';
      case 'html':
      case 'htm':
      case 'css':
        return 'HTML / CSS / JavaScript';
      default:
        return ext ? ext.toUpperCase() : 'C';
    }
  };

  const formatLineNumber = (start: number, end: number): string => {
    if (!start) return '1';
    if (!end || start === end) return String(start);
    return `${start}, ${end}`;
  };

  // 1. Export Without Patched Code (CSV & JSON) - Matches mock2_output Software_*.xlsx
  const exportWithoutPatchesCSV = () => {
    const headers = [
      'SNo',
      'Primary Language of Benchmark',
      'Vulnerability',
      'CVE ID',
      'Severity',
      'Common Weakness Enumeration (CWE) Id',
      'filename with path',
      'line number',
      'Code Snippet at the line'
    ].join(',');

    const rows = findings.map((f, i) => [
      i + 1,
      escapeCsv(getBenchmarkLanguage(f.path)),
      escapeCsv(f.content),
      escapeCsv((f.cve_id && f.cve_id !== 'N/A') ? f.cve_id : (f.ref_cve_id && f.ref_cve_id !== 'N/A') ? f.ref_cve_id : 'N/A'),
      escapeCsv(f.severity.toUpperCase()),
      escapeCsv((f.cwe_id && f.cwe_id !== 'N/A' && f.cwe_id !== 'NONE') ? f.cwe_id : (f.ref_cwe_id && f.ref_cwe_id !== 'N/A') ? f.ref_cwe_id : 'N/A'),
      escapeCsv(f.path),
      escapeCsv(formatLineNumber(f.start_line, f.end_line)),
      escapeCsv(f.existing_code || '')
    ].join(','));

    downloadFile(headers + '\n' + rows.join('\n'), 'benchmark_findings_unpatched.csv', 'text/csv');
  };

  const exportWithoutPatchesJSON = () => {
    const data = findings.map((f, i) => ({
      "SNo": i + 1,
      "Primary Language of Benchmark": getBenchmarkLanguage(f.path),
      "Vulnerability": f.content,
      "CVE ID": (f.cve_id && f.cve_id !== 'N/A') ? f.cve_id : (f.ref_cve_id && f.ref_cve_id !== 'N/A') ? f.ref_cve_id : "N/A",
      "Severity": f.severity.toUpperCase(),
      "Common Weakness Enumeration (CWE) Id": (f.cwe_id && f.cwe_id !== 'N/A' && f.cwe_id !== 'NONE') ? f.cwe_id : (f.ref_cwe_id && f.ref_cwe_id !== 'N/A') ? f.ref_cwe_id : "N/A",
      "filename with path": f.path,
      "line number": formatLineNumber(f.start_line, f.end_line),
      "Code Snippet at the line": f.existing_code || ""
    }));
    downloadFile(JSON.stringify(data, null, 2), 'benchmark_findings_unpatched.json', 'application/json');
  };

  function isConcretePatch(code?: string): boolean {
    if (!code || typeof code !== 'string') return false;
    const trimmed = code.trim();
    if (trimmed.length < 5) return false;
    const withoutComments = trimmed
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*/g, '')
      .replace(/#.*/g, '')
      .trim();
    if (withoutComments.length < 4) return false;
    return /[;{}()=+\-*/<>\[\]]/.test(withoutComments);
  }

  const missingPatchesCount = findings.filter(f => !isConcretePatch(f.suggestion_code)).length;

  const ensureConcretePatches = async (): Promise<Finding[]> => {
    const missing = findings.filter(f => !isConcretePatch(f.suggestion_code));
    if (missing.length === 0) {
      return findings;
    }

    setSynthesizing(true);
    setSynthesisProgress({
      current: 0,
      total: findings.length,
      percent: 0,
      currentPath: missing[0]?.path || '',
      currentLine: missing[0]?.start_line || 1,
      currentCategory: missing[0]?.category || 'Security Defect',
      statusText: `Initializing QbitCode AI for ${missing.length} unpatched findings...`,
      completed: false
    });

    let updatedFindings = findings;

    try {
      const res = await fetch('/api/patches/synthesize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));

                if (data.status === 'success' && data.findings) {
                  updatedFindings = data.findings;
                  setFindings(data.findings);
                }

                if (data.current !== undefined) {
                  setSynthesisProgress(p => ({
                    ...p,
                    current: data.current,
                    total: data.total,
                    percent: data.percent,
                    currentPath: data.path || p.currentPath,
                    currentLine: data.line || p.currentLine,
                    currentCategory: data.category || p.currentCategory,
                    statusText: data.needed
                      ? (data.isDone ? `✔ Patch synthesized for ${data.path}` : `Synthesizing code replacement via vLLM...`)
                      : `Verified existing patch.`
                  }));
                }
              } catch {}
            }
          }
        }
      }

      setSynthesisProgress(p => ({
        ...p,
        percent: 100,
        statusText: `✔ All patches verified and persisted to ocr_output.json!`,
        completed: true
      }));

      // Brief delay to let user observe 100% completion checkmark
      await new Promise(r => setTimeout(r, 800));
      return updatedFindings;
    } catch (err: any) {
      console.error('Failed to synthesize patches:', err);
    } finally {
      setSynthesizing(false);
    }
    return findings;
  };

  // 2. Export With Patched Code (CSV & JSON) - Unified Benchmark & Remediation
  const exportWithPatchesCSV = async () => {
    const readyFindings = await ensureConcretePatches();

    const generateSingleCsv = (items: Finding[], repoTitle = '') => {
      const headers = [
        'SNo',
        'Repository',
        'Primary Language of Benchmark',
        'Vulnerability',
        'CVE ID',
        'Severity',
        'Common Weakness Enumeration (CWE) Id',
        'filename with path',
        'line number',
        'Code Snippet at the line',
        'Patch',
        'Patch Description'
      ].join(',');

      const rows = items.map((f, i) => [
        i + 1,
        escapeCsv(repoTitle || extractRepoName(f.path)),
        escapeCsv(getBenchmarkLanguage(f.path)),
        escapeCsv(f.content),
        escapeCsv((f.cve_id && f.cve_id !== 'N/A') ? f.cve_id : (f.ref_cve_id && f.ref_cve_id !== 'N/A') ? f.ref_cve_id : 'N/A'),
        escapeCsv(f.severity.toUpperCase()),
        escapeCsv((f.cwe_id && f.cwe_id !== 'N/A' && f.cwe_id !== 'NONE') ? f.cwe_id : (f.ref_cwe_id && f.ref_cwe_id !== 'N/A') ? f.ref_cwe_id : 'N/A'),
        escapeCsv(f.path),
        escapeCsv(formatLineNumber(f.start_line, f.end_line)),
        escapeCsv(f.existing_code || ''),
        escapeCsv(f.suggestion_code || ''),
        escapeCsv(f.patch_description || `Remediation for ${f.cwe_id || f.category}: ${f.content.slice(0, 150)}`)
      ].join(','));

      return headers + '\n' + rows.join('\n');
    };

    if (exportScope === 'by_repository') {
      const groups = new Map<string, Finding[]>();
      for (const f of readyFindings) {
        const repo = extractRepoName(f.path);
        if (!groups.has(repo)) groups.set(repo, []);
        groups.get(repo)!.push(f);
      }
      for (const [repoName, repoItems] of groups.entries()) {
        const csv = generateSingleCsv(repoItems, repoName);
        downloadFile(csv, `benchmark_findings_with_patches_${repoName}.csv`, 'text/csv');
      }
    } else {
      const csv = generateSingleCsv(readyFindings);
      downloadFile(csv, 'benchmark_findings_with_patches.csv', 'text/csv');
    }
  };

  const exportWithPatchesJSON = async () => {
    const readyFindings = await ensureConcretePatches();
    const data = readyFindings.map((f, i) => ({
      "SNo": i + 1,
      "Primary Language of Benchmark": getBenchmarkLanguage(f.path),
      "Vulnerability": f.content,
      "CVE ID": (f.cve_id && f.cve_id !== 'N/A') ? f.cve_id : (f.ref_cve_id && f.ref_cve_id !== 'N/A') ? f.ref_cve_id : "N/A",
      "Severity": f.severity.toUpperCase(),
      "Common Weakness Enumeration (CWE) Id": (f.cwe_id && f.cwe_id !== 'N/A' && f.cwe_id !== 'NONE') ? f.cwe_id : (f.ref_cwe_id && f.ref_cwe_id !== 'N/A') ? f.ref_cwe_id : "N/A",
      "filename with path": f.path,
      "line number": formatLineNumber(f.start_line, f.end_line),
      "Code Snippet at the line": f.existing_code || "",
      "Patch": f.suggestion_code || "",
      "Patch Description": f.patch_description || `Remediation for ${f.cwe_id || f.category}: ${f.content.slice(0, 150)}`
    }));
    downloadFile(JSON.stringify(data, null, 2), 'benchmark_findings_with_patches.json', 'application/json');
  };

  // 3. Standalone Patches Only (Matches patches_Software_*.xlsx from mock2_output)
  const exportPatchesOnlyCSV = async () => {
    const readyFindings = await ensureConcretePatches();
    const headers = [
      'SNo',
      'filename with path',
      'Code Snippet at the line',
      'Patch',
      'Patch Description'
    ].join(',');

    const rows = readyFindings.map((f, i) => [
      i + 1,
      escapeCsv(f.path),
      escapeCsv(f.existing_code || ''),
      escapeCsv(f.suggestion_code || ''),
      escapeCsv(f.patch_description || `Remediation for ${f.cwe_id || f.category}: ${f.content.slice(0, 150)}`)
    ].join(','));

    downloadFile(headers + '\n' + rows.join('\n'), 'patches_benchmark.csv', 'text/csv');
  };

  const exportPatchesOnlyJSON = async () => {
    const readyFindings = await ensureConcretePatches();
    const data = readyFindings.map((f, i) => ({
      "SNo": i + 1,
      "filename with path": f.path,
      "Code Snippet at the line": f.existing_code || "",
      "Patch": f.suggestion_code || "",
      "Patch Description": f.patch_description || `Remediation for ${f.cwe_id || f.category}: ${f.content.slice(0, 150)}`
    }));
    downloadFile(JSON.stringify(data, null, 2), 'patches_benchmark.json', 'application/json');
  };

  // Unified Export Handlers
  const handleExportCSV = async () => {
    setExportOpen(false);
    if (exportMode === 'with_patches') {
      await exportWithPatchesCSV();
    } else if (exportMode === 'without_patches') {
      exportWithoutPatchesCSV();
    } else if (exportMode === 'patches_only') {
      await exportPatchesOnlyCSV();
    }
  };

  const handleExportJSON = async () => {
    setExportOpen(false);
    if (exportMode === 'with_patches') {
      await exportWithPatchesJSON();
    } else if (exportMode === 'without_patches') {
      exportWithoutPatchesJSON();
    } else if (exportMode === 'patches_only') {
      await exportPatchesOnlyJSON();
    }
  };


  const exportSARIF = () => {
    const sarif = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: {
          driver: {
            name: "Qbit Code Reviewer",
            version: "1.0.0",
            rules: findings.map(f => ({
              id: f.id,
              shortDescription: { text: f.category },
              defaultConfiguration: { level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning' }
            }))
          }
        },
        results: findings.map(f => ({
          ruleId: f.id,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: { text: f.content },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.path },
              region: { startLine: f.start_line, endLine: f.end_line }
            }
          }]
        }))
      }]
    };
    downloadFile(JSON.stringify(sarif, null, 2), 'qbit_findings.sarif', 'application/json');
  };

  // Metrics
  const totalFindings = findings.length;
  const criticalHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  const mediumLow = findings.filter(f => f.severity === 'medium' || f.severity === 'low').length;
  const fixedCount = findings.filter(f => f.status === 'fixed').length;

  const filteredFindings = findings.filter(f => {
    if (activeFilter === 'critical-high' && f.severity !== 'critical' && f.severity !== 'high') return false;
    if (activeFilter === 'security' && f.category !== 'security') return false;
    if (activeFilter === 'open' && f.status === 'fixed') return false;
    if (activeFilter === 'fixed' && f.status !== 'fixed') return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return f.path.toLowerCase().includes(q) || f.content.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#000000', color: '#e0f2fe', position: 'relative' }}>
      {/* Background Matrix Rain */}
      <MatrixRain />
      
      {/* CRT Scanline Overlay */}
      <div className="crt-overlay" />

      {/* Perspective Grid */}
      <div className="perspective-grid" />

      {/* TOP HEADER */}
      <header className="app-header" style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        minHeight: '70px',
        borderBottom: '1px solid rgba(0, 240, 255, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 24px',
        background: 'rgba(2, 6, 18, 0.96)',
        backdropFilter: 'blur(16px)',
        boxShadow: '0 4px 20px rgba(0, 112, 243, 0.25)',
        gap: '12px',
        flexWrap: 'wrap'
      }}>
        <div className="app-header-left" style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <img
              src="/favicon.png"
              alt="Logo"
              style={{
                width: '30px',
                height: '30px',
                objectFit: 'contain'
              }}
            />
            <div style={{ whiteSpace: 'nowrap' }}>
              <span className="glitch-title app-header-title" style={{ fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
                {titleText}
              </span>
              <span style={{ display: 'inline-block', width: '6px', height: '14px', background: '#00f0ff', marginLeft: '4px', verticalAlign: 'middle', animation: 'pulse 1s infinite' }} />
            </div>
          </div>

          {/* Dynamic vLLM Model Selector Dropdown */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '6px',
            background: 'rgba(0, 112, 243, 0.1)',
            border: '1px solid rgba(0, 112, 243, 0.4)',
            fontSize: '0.75rem',
            whiteSpace: 'nowrap'
          }}>
            <Radio size={12} style={{ color: switchingModel ? '#fbbf24' : '#00f0ff', flexShrink: 0, animation: switchingModel ? 'pulse 1s infinite' : 'none' }} />
            <span style={{ color: '#64748b', fontWeight: 600 }}>vLLM:</span>
            <select
              value={activeModelVariant}
              disabled={switchingModel}
              onChange={(e) => handleSwitchModel(e.target.value)}
              style={{
                background: '#090d16',
                color: activeModelVariant === '7b' ? '#38bdf8' : activeModelVariant === '14b' ? '#00f0ff' : '#d8b4fe',
                border: activeModelVariant === '7b' ? '1px solid rgba(56, 189, 248, 0.4)' : activeModelVariant === '14b' ? '1px solid rgba(0, 240, 255, 0.4)' : '1px solid rgba(168, 85, 247, 0.4)',
                borderRadius: '4px',
                padding: '3px 8px',
                fontSize: '0.73rem',
                fontFamily: '"JetBrains Mono", monospace',
                fontWeight: 700,
                outline: 'none',
                cursor: switchingModel ? 'wait' : 'pointer'
              }}>
              {availableModels.length > 0 ? (
                availableModels.map((m) => (
                  <option 
                    key={m.id} 
                    value={m.id} 
                    style={{ background: '#0f172a', color: m.isDownloaded ? '#f1f5f9' : '#94a3b8' }}>
                    {m.id.toUpperCase()} — {m.badge} {!m.isDownloaded ? '(not downloaded)' : ''}
                  </option>
                ))
              ) : (
                <>
                  <option value="7b">7B — LIGHTWEIGHT RUNNER (8x)</option>
                  <option value="14b">14B — FAST BUG HUNTER (8x)</option>
                  <option value="30b">30B — DEEP FIXER (4x)</option>
                </>
              )}
            </select>
            {switchingModel && <span style={{ color: '#fbbf24', fontSize: '0.68rem', fontWeight: 600, animation: 'pulse 1s infinite' }}>Swapping...</span>}
          </div>
        </div>

        <div className="app-header-right" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          {/* Terminal Console Toggle */}
          <button
            onClick={() => setTerminalOpen(!terminalOpen)}
            style={{
              padding: '8px 14px',
              borderRadius: '6px',
              border: '1px solid rgba(0, 240, 255, 0.3)',
              background: terminalOpen ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 0, 0, 0.4)',
              color: '#00f0ff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.82rem',
              fontFamily: 'Orbitron, sans-serif',
              boxShadow: terminalOpen ? '0 0 12px rgba(0, 240, 255, 0.3)' : 'none'
            }}>
            <Terminal size={14} />
            CONSOLE
          </button>

          {/* Synthesize All Patches Button (Prominently Outside Export) */}
          <button
            onClick={() => ensureConcretePatches()}
            disabled={synthesizing}
            title={missingPatchesCount > 0 ? `${missingPatchesCount} findings need concrete patches` : `All ${findings.length} findings have verified code patches`}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: missingPatchesCount > 0 ? '1px solid rgba(245, 158, 11, 0.7)' : '1px solid rgba(0, 240, 255, 0.5)',
              background: missingPatchesCount > 0 
                ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(0, 112, 243, 0.2))' 
                : 'linear-gradient(135deg, rgba(0, 112, 243, 0.25), rgba(0, 240, 255, 0.15))',
              color: missingPatchesCount > 0 ? '#fbbf24' : '#00f0ff',
              cursor: synthesizing ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '0.82rem',
              fontFamily: 'Orbitron, sans-serif',
              fontWeight: 700,
              boxShadow: missingPatchesCount > 0 ? '0 0 15px rgba(245, 158, 11, 0.25)' : '0 0 15px rgba(0, 240, 255, 0.2)',
              transition: 'all 0.2s ease'
            }}>
            <Zap size={14} style={{ color: missingPatchesCount > 0 ? '#fbbf24' : '#00f0ff' }} />
            <span>SYNTHESIZE PATCHES</span>
            <span style={{
              padding: '2px 7px',
              borderRadius: '10px',
              fontSize: '0.7rem',
              fontWeight: 800,
              background: missingPatchesCount > 0 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(0, 240, 255, 0.2)',
              border: missingPatchesCount > 0 ? '1px solid rgba(245, 158, 11, 0.6)' : '1px solid rgba(0, 240, 255, 0.4)',
              color: missingPatchesCount > 0 ? '#fbbf24' : '#00f0ff'
            }}>
              {missingPatchesCount > 0 ? `${missingPatchesCount} needed` : `${findings.length} ready`}
            </span>
          </button>

          {/* Export Dropdown (Streamlined) */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setExportOpen(!exportOpen)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid rgba(0, 240, 255, 0.3)',
                background: exportOpen ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 240, 255, 0.05)',
                color: '#e0f2fe',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '0.82rem',
                fontFamily: 'Orbitron, sans-serif',
                boxShadow: exportOpen ? '0 0 12px rgba(0, 240, 255, 0.3)' : 'none'
              }}>
              <Download size={14} />
              EXPORT
              <ChevronDown size={13} />
            </button>

            {exportOpen && (
              <div style={{
                position: 'absolute',
                right: 0,
                marginTop: '6px',
                width: '350px',
                background: '#040d21',
                border: '1px solid rgba(0, 240, 255, 0.4)',
                borderRadius: '8px',
                boxShadow: '0 10px 30px rgba(0, 240, 255, 0.35)',
                zIndex: 100,
                overflow: 'hidden',
                backdropFilter: 'blur(12px)'
              }}>
                {/* Header */}
                <div style={{ padding: '10px 14px', background: 'rgba(0, 240, 255, 0.08)', borderBottom: '1px solid rgba(0, 240, 255, 0.15)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.72rem', fontFamily: 'Orbitron, sans-serif', color: '#00f0ff', letterSpacing: '1px', fontWeight: 700 }}>
                    BENCHMARK EXPORT CENTER
                  </span>
                  <span style={{ fontSize: '0.62rem', color: '#64748b' }}>MOCK2 FORMAT</span>
                </div>

                {/* Dataset Segment Selector */}
                <div style={{ padding: '12px 14px 10px 14px' }}>
                  <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, marginBottom: '8px', letterSpacing: '0.5px' }}>
                    1. CHOOSE BENCHMARK DATASET:
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <button
                      onClick={() => setExportMode('with_patches')}
                      style={{
                        padding: '8px 10px',
                        borderRadius: '6px',
                        border: exportMode === 'with_patches' ? '1px solid #00f0ff' : '1px solid rgba(0, 240, 255, 0.15)',
                        background: exportMode === 'with_patches' ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                        color: exportMode === 'with_patches' ? '#00f0ff' : '#94a3b8',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.75rem',
                        fontFamily: 'Orbitron, sans-serif',
                        transition: 'all 0.15s ease'
                      }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Zap size={13} color="#00f0ff" />
                        <span>With Patched Code</span>
                      </span>
                      <span style={{ fontSize: '0.62rem', padding: '1px 6px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.15)', color: '#38bdf8' }}>
                        Recommended
                      </span>
                    </button>

                    <button
                      onClick={() => setExportMode('without_patches')}
                      style={{
                        padding: '8px 10px',
                        borderRadius: '6px',
                        border: exportMode === 'without_patches' ? '1px solid #f59e0b' : '1px solid rgba(245, 158, 11, 0.15)',
                        background: exportMode === 'without_patches' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                        color: exportMode === 'without_patches' ? '#fbbf24' : '#94a3b8',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.75rem',
                        fontFamily: 'Orbitron, sans-serif',
                        transition: 'all 0.15s ease'
                      }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Shield size={13} color="#f59e0b" />
                        <span>Unpatched Findings Only</span>
                      </span>
                      <span style={{ fontSize: '0.62rem', color: '#64748b' }}>Software_*.xlsx</span>
                    </button>

                    <button
                      onClick={() => setExportMode('patches_only')}
                      style={{
                        padding: '8px 10px',
                        borderRadius: '6px',
                        border: exportMode === 'patches_only' ? '1px solid #a855f7' : '1px solid rgba(168, 85, 247, 0.15)',
                        background: exportMode === 'patches_only' ? 'rgba(168, 85, 247, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                        color: exportMode === 'patches_only' ? '#c084fc' : '#94a3b8',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.75rem',
                        fontFamily: 'Orbitron, sans-serif',
                        transition: 'all 0.15s ease'
                      }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Layers size={13} color="#a855f7" />
                        <span>Patches Only</span>
                      </span>
                      <span style={{ fontSize: '0.62rem', color: '#64748b' }}>patches_*.xlsx</span>
                    </button>
                  </div>
                  {/* Repository Scope Selector (Single vs Multi-Repo) */}
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, marginBottom: '6px', letterSpacing: '0.5px' }}>
                      2. EXPORT SCOPE:
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                      <button
                        onClick={() => setExportScope('consolidated')}
                        style={{
                          padding: '6px 8px',
                          borderRadius: '5px',
                          border: exportScope === 'consolidated' ? '1px solid #00f0ff' : '1px solid rgba(0, 240, 255, 0.15)',
                          background: exportScope === 'consolidated' ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                          color: exportScope === 'consolidated' ? '#00f0ff' : '#94a3b8',
                          cursor: 'pointer',
                          fontSize: '0.72rem',
                          fontFamily: 'Orbitron, sans-serif'
                        }}>
                        Consolidated
                      </button>
                      <button
                        onClick={() => setExportScope('by_repository')}
                        style={{
                          padding: '6px 8px',
                          borderRadius: '5px',
                          border: exportScope === 'by_repository' ? '1px solid #00f0ff' : '1px solid rgba(0, 240, 255, 0.15)',
                          background: exportScope === 'by_repository' ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                          color: exportScope === 'by_repository' ? '#00f0ff' : '#94a3b8',
                          cursor: 'pointer',
                          fontSize: '0.72rem',
                          fontFamily: 'Orbitron, sans-serif'
                        }}>
                        Per-Repository
                      </button>
                    </div>
                  </div>
                </div>

                {/* Format Action Buttons */}
                <div style={{ padding: '10px 14px 14px 14px', borderTop: '1px solid rgba(0, 240, 255, 0.1)', background: 'rgba(0, 0, 0, 0.25)' }}>
                  <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, marginBottom: '8px', letterSpacing: '0.5px' }}>
                    3. DOWNLOAD BENCHMARK:
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <button
                      onClick={handleExportCSV}
                      style={{
                        padding: '9px 12px',
                        background: 'linear-gradient(135deg, rgba(0, 112, 243, 0.3), rgba(0, 240, 255, 0.2))',
                        border: '1px solid rgba(0, 240, 255, 0.4)',
                        borderRadius: '6px',
                        color: '#00f0ff',
                        fontSize: '0.76rem',
                        fontWeight: 700,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                        fontFamily: 'Orbitron, sans-serif',
                        boxShadow: '0 0 10px rgba(0, 240, 255, 0.15)'
                      }}>
                      <FileSpreadsheet size={13} />
                      CSV FORMAT
                    </button>
                    <button
                      onClick={handleExportJSON}
                      style={{
                        padding: '9px 12px',
                        background: 'linear-gradient(135deg, rgba(0, 112, 243, 0.3), rgba(0, 240, 255, 0.2))',
                        border: '1px solid rgba(0, 240, 255, 0.4)',
                        borderRadius: '6px',
                        color: '#00f0ff',
                        fontSize: '0.76rem',
                        fontWeight: 700,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                        fontFamily: 'Orbitron, sans-serif',
                        boxShadow: '0 0 10px rgba(0, 240, 255, 0.15)'
                      }}>
                      <FileCode size={13} />
                      JSON FORMAT
                    </button>
                  </div>
                </div>

                {/* Footer SARIF Option */}
                <div style={{ padding: '8px 14px', borderTop: '1px solid rgba(0, 240, 255, 0.08)', background: '#020612' }}>
                  <button
                    onClick={exportSARIF}
                    style={{ width: '100%', padding: '4px 0', textAlign: 'left', background: 'none', border: 'none', color: '#64748b', fontSize: '0.7rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', fontFamily: '"JetBrains Mono", monospace' }}>
                    <Shield size={11} color="#38bdf8" /> SARIF 2.1 Telemetry Report
                  </button>
                </div>
              </div>
            )}
          </div>


          <button 
            onClick={handleRunReview} 
            disabled={loading}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: '1px solid rgba(0, 240, 255, 0.3)',
              background: 'rgba(0, 112, 243, 0.15)',
              color: '#38bdf8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.82rem',
              fontFamily: 'Orbitron, sans-serif'
            }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            GIT REVIEW
          </button>

          {/* Severity Policy Toggle (Default: HIGH & CRITICAL) */}
          <button
            onClick={() => {
              const next = minSeverityFilter === 'high' ? 'all' : 'high';
              setMinSeverityFilter(next);
              setActiveFilter(next === 'high' ? 'critical-high' : 'all');
            }}
            title={minSeverityFilter === 'high' ? 'Currently auditing HIGH & CRITICAL only (click to include Low/Medium)' : 'Auditing ALL severities (click to filter to High & Critical only)'}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: minSeverityFilter === 'high' ? '1px solid #ef4444' : '1px solid rgba(0, 240, 255, 0.3)',
              background: minSeverityFilter === 'high' ? 'rgba(239, 68, 68, 0.18)' : 'rgba(0, 0, 0, 0.4)',
              color: minSeverityFilter === 'high' ? '#f87171' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.78rem',
              fontWeight: 700,
              fontFamily: 'Orbitron, sans-serif',
              boxShadow: minSeverityFilter === 'high' ? '0 0 12px rgba(239, 68, 68, 0.3)' : 'none',
              transition: 'all 0.2s ease'
            }}>
            <Shield size={13} color={minSeverityFilter === 'high' ? '#f87171' : '#94a3b8'} />
            <span>{minSeverityFilter === 'high' ? 'CRIT / HIGH ONLY' : 'ALL SEVERITIES'}</span>
          </button>

          {/* FastScan Button (Immediate 1-Click Scan with Precomputed Estimate) */}
          <button 
            onClick={() => handleDirectFastScan(scanPath)}
            disabled={loading}
            title={`FastScan: Instantly dispatch accelerated scan without non-code & tests. (Predicted duration: ${workspaceEstimate?.fastEtaFormatted || '~3h'})`}
            style={{
              padding: '8px 14px',
              borderRadius: '6px',
              border: '1px solid rgba(255, 184, 0, 0.6)',
              background: 'linear-gradient(135deg, rgba(255, 184, 0, 0.25), rgba(255, 85, 0, 0.35))',
              color: '#ffb800',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.82rem',
              fontWeight: 800,
              fontFamily: 'Orbitron, sans-serif',
              boxShadow: '0 0 15px rgba(255, 184, 0, 0.35)',
              transition: 'all 0.2s ease'
            }}>
            <Zap size={14} style={{ filter: 'drop-shadow(0 0 4px #ffb800)' }} />
            <span>{loading ? 'SWEEPING...' : '⚡ FASTSCAN'}</span>
            {!loading && workspaceEstimate?.fastEtaFormatted && (
              <span style={{
                fontSize: '0.68rem',
                padding: '1px 5px',
                borderRadius: '4px',
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(255, 184, 0, 0.3)',
                color: '#fef08a',
                fontFamily: '"JetBrains Mono", monospace'
              }}>
                {workspaceEstimate.fastEtaFormatted}
              </span>
            )}
          </button>

          {/* SuperFast Scan Control with Customizable Hours */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.25), rgba(5, 150, 105, 0.35))',
            border: '1px solid rgba(16, 185, 129, 0.7)',
            borderRadius: '6px',
            boxShadow: '0 0 15px rgba(16, 185, 129, 0.35)',
            overflow: 'hidden'
          }}>
            <button 
              onClick={() => handleDirectSuperFastScan(scanPath)}
              disabled={loading}
              title={`SuperFast Scan: Immediately dispatch scan guaranteed under ${superFastHours} hours by auto-pruning heaviest modules`}
              style={{
                padding: '8px 12px',
                border: 'none',
                background: 'transparent',
                color: '#34d399',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '0.82rem',
                fontWeight: 800,
                fontFamily: 'Orbitron, sans-serif',
                transition: 'all 0.2s ease'
              }}>
              <Zap size={14} color="#34d399" style={{ filter: 'drop-shadow(0 0 4px #34d399)' }} />
              {loading ? 'SWEEPING...' : `⚡ SUPERFAST <${superFastHours}H`}
            </button>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              padding: '0 8px',
              borderLeft: '1px solid rgba(16, 185, 129, 0.4)',
              background: 'rgba(0, 0, 0, 0.3)'
            }}>
              <input
                type="number"
                min="0.5"
                max="24"
                step="0.5"
                value={superFastHours}
                onChange={(e) => setSuperFastHours(Math.max(0.1, parseFloat(e.target.value) || 1.0))}
                title="Customize SuperFast maximum scan duration ceiling (hours)"
                style={{
                  width: '42px',
                  padding: '2px 4px',
                  background: 'rgba(0, 0, 0, 0.6)',
                  border: '1px solid rgba(16, 185, 129, 0.5)',
                  borderRadius: '4px',
                  color: '#34d399',
                  fontSize: '0.74rem',
                  fontFamily: '"JetBrains Mono", monospace',
                  textAlign: 'center',
                  fontWeight: 700
                }}
              />
              <span style={{ fontSize: '0.66rem', color: '#94a3b8', marginLeft: '4px', fontFamily: 'Orbitron, sans-serif' }}>H</span>
            </div>
          </div>

          {/* Full Scan Button */}
          <button 
            onClick={() => handleRunScan(scanPath || '')} 
            disabled={loading}
            title={scanPath ? `Scan target: ${scanPath}` : "Scan the entire repository from root"}
            style={{
              padding: '8px 18px',
              borderRadius: '6px',
              border: 'none',
              background: loading ? 'rgba(0, 112, 243, 0.4)' : 'linear-gradient(135deg, #0070f3, #00f0ff)',
              color: '#000',
              cursor: loading ? 'default' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.85rem',
              fontWeight: 800,
              fontFamily: 'Orbitron, sans-serif',
              boxShadow: loading ? 'none' : '0 0 20px rgba(0, 240, 255, 0.5)'
            }}>
            <Search size={14} />
            {loading ? 'SWEEPING...' : 'FULL SCAN'}
          </button>

          {/* Stop Scan Button when active */}
          {loading && (
            <button 
              onClick={handleStopScan}
              title="Abort the current running scan"
              style={{
                padding: '8px 16px',
                borderRadius: '6px',
                border: '1px solid rgba(239, 68, 68, 0.6)',
                background: 'rgba(239, 68, 68, 0.2)',
                color: '#f87171',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '0.82rem',
                fontWeight: 700,
                fontFamily: 'Orbitron, sans-serif',
                boxShadow: '0 0 15px rgba(239, 68, 68, 0.4)'
              }}>
              <X size={14} />
              STOP
            </button>
          )}
        </div>
      </header>

      {/* METRICS BANNER */}
      <section className="metrics-grid" style={{
        padding: '20px 24px 0 24px',
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '16px',
        alignItems: 'center',
        zIndex: 5
      }}>
        <div style={{ padding: '16px 20px', borderRadius: '10px', background: 'rgba(3, 8, 22, 0.85)', border: '1px solid rgba(0, 240, 255, 0.25)', boxShadow: '0 0 15px rgba(0, 240, 255, 0.1)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <Shield style={{ color: '#00f0ff', filter: 'drop-shadow(0 0 6px #00f0ff)' }} size={28} />
          <div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>DETECTED FLAWS</div>
            <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#00f0ff', textShadow: '0 0 10px #00f0ff' }}>{totalFindings}</div>
          </div>
        </div>

        <div style={{ padding: '16px 20px', borderRadius: '10px', background: 'rgba(3, 8, 22, 0.85)', border: '1px solid rgba(0, 112, 243, 0.3)', boxShadow: '0 0 15px rgba(0, 112, 243, 0.1)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <AlertCircle style={{ color: '#38bdf8' }} size={28} />
          <div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>CRITICAL & HIGH</div>
            <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#38bdf8', textShadow: '0 0 10px #38bdf8' }}>{criticalHigh}</div>
          </div>
        </div>

        <div style={{ padding: '16px 20px', borderRadius: '10px', background: 'rgba(3, 8, 22, 0.85)', border: '1px solid rgba(0, 240, 255, 0.2)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <AlertTriangle style={{ color: '#0070f3' }} size={28} />
          <div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>MEDIUM & LOW</div>
            <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#60a5fa' }}>{mediumLow}</div>
          </div>
        </div>

        <div style={{ padding: '16px 20px', borderRadius: '10px', background: 'rgba(3, 8, 22, 0.85)', border: '1px solid rgba(0, 240, 255, 0.3)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <CheckCircle2 style={{ color: '#00f0ff' }} size={28} />
          <div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>REMEDIATED</div>
            <div style={{ fontSize: '1.7rem', fontWeight: 800, color: '#00f0ff', textShadow: '0 0 10px #00f0ff' }}>{fixedCount}</div>
          </div>
        </div>
      </section>

      {/* SCANNING PROGRESS & DUAL ETA BANNER */}
      {loading && (
        <section style={{ padding: '12px 24px 0 24px', zIndex: 5 }}>
          <div style={{
            background: 'rgba(3, 8, 22, 0.95)',
            border: '1px solid #00f0ff',
            borderRadius: '8px',
            padding: '12px 18px',
            boxShadow: '0 0 20px rgba(0, 240, 255, 0.25)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}>
            {/* Top Row: Sub-Repo Scope or Workspace Status */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', fontFamily: 'Orbitron, sans-serif', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#00f0ff' }}>
                <span className="animate-spin">⚙</span>
                <span>
                  {scanProgress.currentSubrepo 
                    ? `SCANNING REPO [${scanProgress.subrepoIndex || 1}/${scanProgress.totalSubrepos || 1}]: ${scanProgress.currentSubrepo}` 
                    : `SCAN IN PROGRESS: ${scanPath || 'FULL WORKSPACE'}`}
                </span>
              </div>
              <div style={{ color: '#38bdf8', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem' }}>
                {scanProgress.totalFiles > 0 
                  ? `Audited: ${scanProgress.reviewedFiles} / ${scanProgress.totalFiles} files (${scanProgress.percent}%)`
                  : 'Discovering files & calculating AST graph...'}
                {scanProgress.skippedFiles > 0 && ` (${scanProgress.skippedFiles} cached/skipped)`}
                {scanProgress.estimatedTokens && ` • ~${scanProgress.estimatedTokens} tokens`}
              </div>
            </div>

            {/* Dual ETA & Multi-Repo Progress Details */}
            {((scanProgress.totalSubrepos ?? 0) > 1 || scanProgress.totalFiles > 0) && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.74rem',
                fontFamily: '"JetBrains Mono", monospace',
                background: 'rgba(0, 240, 255, 0.05)',
                padding: '6px 12px',
                borderRadius: '6px',
                border: '1px solid rgba(0, 240, 255, 0.15)',
                flexWrap: 'wrap',
                gap: '8px'
              }}>
                {/* Sub-Repo Level ETA */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ color: '#64748b' }}>Current Sub-Repo ETA:</span>
                  <span style={{ color: '#38bdf8', fontWeight: 700 }}>
                    ~{scanProgress.etaFormatted || 'Calculating...'}
                  </span>
                </div>

                {/* Overall Entire Repository / Workspace ETA */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ color: '#64748b' }}>Entire Repo Scan ETA:</span>
                  <span style={{ color: '#00f0ff', fontWeight: 700 }}>
                    ~{scanProgress.overallEtaFormatted || scanProgress.etaFormatted || 'Calculating...'}
                  </span>
                  {(scanProgress.totalSubrepos ?? 0) > 1 && (
                    <span style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                      ({scanProgress.completedSubrepos || 0}/{scanProgress.totalSubrepos} Sub-Units Finished)
                    </span>
                  )}
                </div>
              </div>
            )}

            <div style={{ width: '100%', height: '6px', background: '#020612', borderRadius: '3px', overflow: 'hidden', border: '1px solid rgba(0, 240, 255, 0.3)' }}>
              <div style={{
                width: `${scanProgress.percent > 0 ? scanProgress.percent : 15}%`,
                height: '100%',
                background: 'linear-gradient(90deg, #0070f3, #00f0ff)',
                boxShadow: '0 0 10px #00f0ff',
                transition: 'width 0.3s ease'
              }} />
            </div>
          </div>
        </section>
      )}

      {/* MAIN VIEW MODE SWITCHER (CODE AUDIT vs PACKAGE VULNERABILITIES) */}
      <div style={{ padding: '0 24px', display: 'flex', gap: '12px', alignItems: 'center', zIndex: 5, marginTop: '8px' }}>
        <button
          onClick={() => setMainView('code')}
          style={{
            padding: '8px 18px',
            borderRadius: '6px',
            border: mainView === 'code' ? '1px solid #00f0ff' : '1px solid rgba(0, 240, 255, 0.2)',
            background: mainView === 'code' ? 'rgba(0, 240, 255, 0.15)' : 'rgba(3, 8, 22, 0.7)',
            color: mainView === 'code' ? '#00f0ff' : '#94a3b8',
            fontFamily: 'Orbitron, sans-serif',
            fontSize: '0.82rem',
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: mainView === 'code' ? '0 0 15px rgba(0, 240, 255, 0.3)' : 'none'
          }}>
          <Shield size={14} />
          <span>CODE AUDIT ({findings.length})</span>
        </button>

        <button
          onClick={() => {
            setMainView('packages');
            if (!scaReport && !scaLoading) fetchScaReport();
          }}
          style={{
            padding: '8px 18px',
            borderRadius: '6px',
            border: mainView === 'packages' ? '1px solid #f59e0b' : '1px solid rgba(245, 158, 11, 0.2)',
            background: mainView === 'packages' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(3, 8, 22, 0.7)',
            color: mainView === 'packages' ? '#fbbf24' : '#94a3b8',
            fontFamily: 'Orbitron, sans-serif',
            fontSize: '0.82rem',
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: mainView === 'packages' ? '0 0 15px rgba(245, 158, 11, 0.3)' : 'none'
          }}>
          <Package size={14} />
          <span>PACKAGE VULNERABILITIES (SCA 8082){scaReport?.summary?.vulnerable_packages !== undefined ? ` [${scaReport.summary.vulnerable_packages}]` : ''}</span>
        </button>

        {mainView === 'packages' && (
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '0.74rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>
              TARGET: <span style={{ color: '#00f0ff' }}>{scanPath ? scanPath.split('/').pop() : 'FULL WORKSPACE'}</span>
            </span>
            <button
              onClick={() => fetchScaReport(scanPath)}
              disabled={scaLoading}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: '1px solid rgba(245, 158, 11, 0.4)',
                background: 'rgba(245, 158, 11, 0.1)',
                color: '#fbbf24',
                cursor: scaLoading ? 'wait' : 'pointer',
                fontSize: '0.74rem',
                fontFamily: 'Orbitron, sans-serif',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}>
              <RefreshCw size={12} className={scaLoading ? 'animate-spin' : ''} />
              {scaLoading ? 'SCANNING PACKAGES...' : 'RE-SCAN PACKAGES'}
            </button>
          </div>
        )}
      </div>

      {mainView === 'packages' ? (
        /* PACKAGE VULNERABILITIES SCA VIEW */
        <main style={{ flex: 1, padding: '20px 24px', zIndex: 5, display: 'flex', flexDirection: 'column', gap: '20px', paddingBottom: terminalOpen ? '320px' : '40px' }}>
          {/* SCA Header Banner */}
          <div className="sca-summary-grid" style={{
            background: 'rgba(3, 8, 22, 0.95)',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            boxShadow: '0 0 20px rgba(245, 158, 11, 0.15)',
            borderRadius: '10px',
            padding: '20px',
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '16px'
          }}>
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>MANIFEST AUDITED</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc', marginTop: '4px' }}>
                {scaReport?.repo_name || 'Current Workspace'}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px', fontFamily: '"JetBrains Mono", monospace' }}>
                {Object.keys(scaReport?.manifest_files || {}).join(', ') || 'Scanning package.json, pom.xml, requirements.txt...'}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>TOTAL DEPENDENCIES</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#38bdf8', marginTop: '4px' }}>
                {scaReport?.summary?.total_packages ?? '...'}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#10b981' }}>
                ✓ {scaReport?.summary?.clean_packages ?? 0} clean packages
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>ACTIONABLE RISKS</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ef4444', marginTop: '4px', textShadow: '0 0 10px rgba(239, 68, 68, 0.5)' }}>
                {scaReport?.summary?.actionable_active_risks ?? 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#fca5a5' }}>
                Actively imported in codebase
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>DORMANT RISKS</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f59e0b', marginTop: '4px' }}>
                {scaReport?.summary?.dormant_manifest_risks ?? 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#fcd34d' }}>
                Declared in manifest (unused)
              </div>
            </div>
          </div>

          {scaError && (
            <div style={{ padding: '16px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#fca5a5', fontSize: '0.85rem' }}>
              ⚠️ {scaError}
            </div>
          )}

          {/* Actionable Active Risks List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'Orbitron, sans-serif', color: '#00f0ff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertCircle size={16} color="#ef4444" />
              <span>ACTIVE VULNERABLE DEPENDENCIES (IMPORTED & USED IN CODE)</span>
            </div>

            {scaReport?.actionable_risks && scaReport.actionable_risks.length > 0 ? (
              scaReport.actionable_risks.map((pkg, idx) => {
                const pkgKey = `active-${pkg.package}-${idx}`;
                const isExpanded = !!expandedScaPkgs[pkgKey];
                const cves = pkg.vulnerabilities || [];
                const cveIds = pkg.cve_summary || cves.map(v => v.cve_id);

                return (
                  <div key={idx} style={{
                    background: '#030816',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    borderLeft: '4px solid #ef4444',
                    boxShadow: '0 0 16px rgba(239, 68, 68, 0.12)',
                    borderRadius: '8px',
                    padding: '16px 20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', fontFamily: '"JetBrains Mono", monospace' }}>
                          {pkg.package}
                        </span>
                        <span style={{ fontSize: '0.72rem', background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.5)', color: '#f87171', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                          {pkg.highest_severity}
                        </span>
                        <span style={{ fontSize: '0.72rem', background: 'rgba(0, 112, 243, 0.2)', color: '#38bdf8', padding: '2px 8px', borderRadius: '4px' }}>
                          {pkg.ecosystem}
                        </span>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                          Installed: <strong style={{ color: '#fff' }}>{pkg.installed_version}</strong>
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        {pkg.recommended_fix && (
                          <div style={{
                            padding: '4px 12px',
                            borderRadius: '6px',
                            background: 'rgba(16, 185, 129, 0.15)',
                            border: '1px solid rgba(16, 185, 129, 0.4)',
                            color: '#34d399',
                            fontSize: '0.76rem',
                            fontWeight: 700,
                            fontFamily: 'Orbitron, sans-serif'
                          }}>
                            ⚡ UPGRADE TO: {pkg.recommended_fix}
                          </div>
                        )}

                        {(cves.length > 0 || cveIds.length > 0) && (
                          <button
                            onClick={() => setExpandedScaPkgs(prev => ({ ...prev, [pkgKey]: !prev[pkgKey] }))}
                            style={{
                              padding: '4px 10px',
                              borderRadius: '4px',
                              border: '1px solid rgba(0, 240, 255, 0.3)',
                              background: isExpanded ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 0, 0, 0.4)',
                              color: '#00f0ff',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px',
                              fontSize: '0.72rem',
                              fontFamily: 'Orbitron, sans-serif'
                            }}>
                            {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                            {cves.length || cveIds.length} CVEs & ADVISORIES
                          </button>
                        )}
                      </div>
                    </div>

                    <div style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                      <span>Declared in: <code style={{ color: '#00f0ff' }}>{pkg.manifest_file}</code></span>
                      <span>Status: <strong style={{ color: '#ef4444' }}>ACTIVE (Import count: {pkg.code_usage?.import_count || 1})</strong></span>
                    </div>

                    {/* CVE & Advisory Pill Summary */}
                    {cveIds.length > 0 && !isExpanded && (
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.68rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>AFFECTED CVEs:</span>
                        {cveIds.slice(0, 6).map((cve, cIdx) => (
                          <a
                            key={cIdx}
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              fontSize: '0.68rem',
                              color: '#f87171',
                              background: 'rgba(239, 68, 68, 0.12)',
                              border: '1px solid rgba(239, 68, 68, 0.3)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              textDecoration: 'none',
                              fontFamily: '"JetBrains Mono", monospace'
                            }}>
                            {cve}
                          </a>
                        ))}
                        {cveIds.length > 6 && (
                          <span style={{ fontSize: '0.68rem', color: '#94a3b8' }}>+{cveIds.length - 6} more</span>
                        )}
                      </div>
                    )}

                    {/* Detailed CVE Dropdown Table */}
                    {isExpanded && cves.length > 0 && (
                      <div style={{
                        marginTop: '8px',
                        background: '#020612',
                        border: '1px solid rgba(0, 240, 255, 0.2)',
                        borderRadius: '6px',
                        padding: '12px 14px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px'
                      }}>
                        <div style={{ fontSize: '0.72rem', color: '#00f0ff', fontFamily: 'Orbitron, sans-serif', fontWeight: 700 }}>
                          DETECTED CVEs & VULNERABILITY BREAKDOWN ({cves.length}):
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          {cves.map((vul, vIdx) => (
                            <div key={vIdx} style={{
                              padding: '8px 12px',
                              borderRadius: '5px',
                              background: 'rgba(255, 255, 255, 0.02)',
                              border: '1px solid rgba(255, 255, 255, 0.06)',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '4px'
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <a
                                    href={`https://nvd.nist.gov/vuln/detail/${vul.cve_id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    style={{
                                      fontSize: '0.75rem',
                                      fontWeight: 700,
                                      color: '#f87171',
                                      textDecoration: 'none',
                                      fontFamily: '"JetBrains Mono", monospace'
                                    }}>
                                    {vul.cve_id}
                                  </a>
                                  {vul.cwe && (
                                    <span style={{ fontSize: '0.68rem', color: '#38bdf8', background: 'rgba(0, 112, 243, 0.2)', padding: '1px 6px', borderRadius: '3px' }}>
                                      {vul.cwe}
                                    </span>
                                  )}
                                  <span style={{
                                    fontSize: '0.68rem',
                                    fontWeight: 700,
                                    padding: '1px 6px',
                                    borderRadius: '3px',
                                    color: vul.severity === 'CRITICAL' || vul.severity === 'HIGH' ? '#f87171' : '#fbbf24',
                                    background: vul.severity === 'CRITICAL' || vul.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)'
                                  }}>
                                    {vul.severity}
                                  </span>
                                </div>
                                {vul.fixed_in && (
                                  <span style={{ fontSize: '0.7rem', color: '#34d399', fontFamily: '"JetBrains Mono", monospace' }}>
                                    Fixed in: {vul.fixed_in}
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '0.76rem', color: '#cbd5e1', lineHeight: 1.4 }}>
                                {vul.title}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {pkg.code_usage?.traces && pkg.code_usage.traces.length > 0 && (
                      <div style={{ background: '#020612', border: '1px solid rgba(0, 240, 255, 0.15)', borderRadius: '6px', padding: '10px 14px' }}>
                        <div style={{ fontSize: '0.7rem', color: '#64748b', marginBottom: '6px', fontFamily: 'Orbitron, sans-serif' }}>CODE TRACE:</div>
                        {pkg.code_usage.traces.map((trace, tIdx) => (
                          <div key={tIdx} style={{ fontSize: '0.76rem', fontFamily: '"JetBrains Mono", monospace', color: '#e0f2fe' }}>
                            <span style={{ color: '#38bdf8' }}>{trace.file}:{trace.line}</span> &rarr; <code style={{ color: '#fbbf24' }}>{trace.snippet}</code>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', background: '#030816', border: '1px solid rgba(0, 240, 255, 0.2)', borderRadius: '8px', color: '#94a3b8', fontSize: '0.85rem' }}>
                {scaLoading ? 'Scanning repository packages...' : 'No actionable active vulnerabilities detected in imported packages! 🎉'}
              </div>
            )}

            {/* Dormant Risks Section */}
            {scaReport?.dormant_risks && scaReport.dormant_risks.length > 0 && (
              <>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'Orbitron, sans-serif', color: '#fbbf24', marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Shield size={16} color="#fbbf24" />
                  <span>DORMANT MANIFEST PACKAGES ({scaReport.dormant_risks.length})</span>
                </div>
                {scaReport.dormant_risks.map((pkg, idx) => {
                  const pkgKey = `dormant-${pkg.package}-${idx}`;
                  const isExpanded = !!expandedScaPkgs[pkgKey];
                  const cves = pkg.vulnerabilities || [];
                  const cveIds = pkg.cve_summary || cves.map(v => v.cve_id);

                  return (
                    <div key={idx} style={{
                      background: '#030816',
                      border: '1px solid rgba(245, 158, 11, 0.2)',
                      borderRadius: '8px',
                      padding: '12px 18px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                          <span style={{ color: '#f8fafc', fontWeight: 600 }}>{pkg.package}</span>
                          <span style={{ fontSize: '0.7rem', color: '#fbbf24', background: 'rgba(245, 158, 11, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                            {pkg.highest_severity}
                          </span>
                          <span style={{ fontSize: '0.7rem', color: '#64748b' }}>v{pkg.installed_version} ({pkg.manifest_file})</span>
                          {pkg.recommended_fix && (
                            <span style={{ fontSize: '0.75rem', color: '#34d399' }}>Fix: {pkg.recommended_fix}</span>
                          )}
                        </div>
                        {(cves.length > 0 || cveIds.length > 0) && (
                          <button
                            onClick={() => setExpandedScaPkgs(prev => ({ ...prev, [pkgKey]: !prev[pkgKey] }))}
                            style={{
                              padding: '3px 8px',
                              borderRadius: '4px',
                              border: '1px solid rgba(245, 158, 11, 0.3)',
                              background: isExpanded ? 'rgba(245, 158, 11, 0.15)' : 'none',
                              color: '#fbbf24',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                              fontSize: '0.7rem',
                              fontFamily: 'Orbitron, sans-serif'
                            }}>
                            {isExpanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                            {cves.length || cveIds.length} CVEs
                          </button>
                        )}
                      </div>

                      {/* Dormant CVE list */}
                      {isExpanded && cves.length > 0 && (
                        <div style={{
                          marginTop: '6px',
                          background: '#020612',
                          border: '1px solid rgba(245, 158, 11, 0.2)',
                          borderRadius: '6px',
                          padding: '10px 12px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '6px'
                        }}>
                          {cves.map((vul, vIdx) => (
                            <div key={vIdx} style={{ fontSize: '0.74rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                              <span style={{ color: '#f87171', fontFamily: '"JetBrains Mono", monospace' }}>{vul.cve_id}</span>
                              <span style={{ color: '#94a3b8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{vul.title}</span>
                              {vul.fixed_in && <span style={{ color: '#34d399' }}>Fix: {vul.fixed_in}</span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </main>
      ) : (
      /* MAIN TWO-COLUMN SPLIT */
      <main className="main-split-container" style={{ flex: 1, display: 'flex', padding: '20px 24px', gap: '24px', zIndex: 5, paddingBottom: terminalOpen ? '320px' : '40px' }}>
        {/* Left Column: Finding Cards */}
        <section style={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
          {/* Filter & View Mode Bar */}
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
              <Search size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#00f0ff' }} />
              <input
                type="text"
                placeholder="Filter vulnerability vector / file path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 12px 10px 38px',
                  borderRadius: '6px',
                  background: 'rgba(2, 6, 18, 0.8)',
                  border: '1px solid rgba(0, 240, 255, 0.3)',
                  boxShadow: 'inset 0 0 10px rgba(0, 240, 255, 0.1)',
                  color: '#fff',
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            {/* Severity / Status Filter Pills */}
            <div style={{ display: 'flex', gap: '6px', background: 'rgba(0, 240, 255, 0.05)', padding: '3px', borderRadius: '6px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
              {(['all', 'critical-high', 'security', 'open', 'fixed'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveFilter(tab)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '0.75rem',
                    fontFamily: 'Orbitron, sans-serif',
                    fontWeight: 600,
                    background: activeFilter === tab ? '#0070f3' : 'transparent',
                    color: activeFilter === tab ? '#fff' : '#64748b',
                    boxShadow: activeFilter === tab ? '0 0 10px #0070f3' : 'none',
                    cursor: 'pointer'
                  }}>
                  {tab === 'critical-high' ? 'CRIT/HIGH' : tab.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Directory Grouping Toggle */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(0, 240, 255, 0.05)', padding: '3px', borderRadius: '6px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
              <button
                onClick={() => setGroupByFolder(false)}
                title="View all findings in a flat list"
                style={{
                  padding: '6px 10px',
                  borderRadius: '4px',
                  border: 'none',
                  fontSize: '0.73rem',
                  fontFamily: 'Orbitron, sans-serif',
                  fontWeight: 600,
                  background: !groupByFolder ? 'rgba(0, 240, 255, 0.2)' : 'transparent',
                  color: !groupByFolder ? '#00f0ff' : '#64748b',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                <Code2 size={12} />
                FLAT
              </button>
              <button
                onClick={() => setGroupByFolder(true)}
                title="Group findings by repository and directory"
                style={{
                  padding: '6px 10px',
                  borderRadius: '4px',
                  border: 'none',
                  fontSize: '0.73rem',
                  fontFamily: 'Orbitron, sans-serif',
                  fontWeight: 600,
                  background: groupByFolder ? 'rgba(0, 240, 255, 0.2)' : 'transparent',
                  color: groupByFolder ? '#00f0ff' : '#64748b',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                <FolderOpen size={12} />
                GROUPED
              </button>
            </div>
          </div>

          {/* Finding Cards Container */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {(() => {
              // Helper to render individual finding card
              const renderFindingCard = (finding: Finding) => (
                <div key={finding.id} style={{
                  background: '#030816',
                  border: '1px solid rgba(0, 240, 255, 0.25)',
                  borderLeft: `4px solid ${finding.severity === 'critical' || finding.severity === 'high' ? '#00f0ff' : '#0070f3'}`,
                  boxShadow: '0 0 16px rgba(0, 240, 255, 0.12)',
                  borderRadius: '8px',
                  overflow: 'hidden'
                }}>
                  <div style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid rgba(0, 240, 255, 0.1)' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                        <span style={{
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          fontFamily: 'Orbitron, sans-serif',
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: 'rgba(0, 240, 255, 0.15)',
                          color: '#00f0ff',
                          boxShadow: '0 0 8px rgba(0, 240, 255, 0.4)'
                        }}>
                          {finding.severity}
                        </span>
                        <span style={{ fontSize: '0.68rem', background: 'rgba(0, 112, 243, 0.2)', padding: '2px 8px', borderRadius: '4px', color: '#38bdf8', fontFamily: '"JetBrains Mono", monospace' }}>
                          {finding.category}
                        </span>
                        {/* Ground-Truth CWE */}
                        {finding.cwe_id && finding.cwe_id !== 'NONE' && finding.cwe_id !== 'N/A' && (
                          <span
                            title={finding.cwe_title ? `${finding.cwe_id}: ${finding.cwe_title}` : finding.cwe_id}
                            style={{
                              fontSize: '0.68rem',
                              background: 'rgba(138, 43, 226, 0.25)',
                              border: '1px solid rgba(138, 43, 226, 0.6)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              color: '#c084fc',
                              fontFamily: '"JetBrains Mono", monospace',
                              fontWeight: 700
                            }}
                          >
                            🛡️ {finding.cwe_id}
                          </span>
                        )}
                        {/* Ground-Truth CVE */}
                        {finding.cve_id && finding.cve_id !== 'N/A' && (
                          <span
                            title={`Detected CVE: ${finding.cve_id}`}
                            style={{
                              fontSize: '0.68rem',
                              background: 'rgba(239, 68, 68, 0.2)',
                              border: '1px solid rgba(239, 68, 68, 0.5)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              color: '#f87171',
                              fontFamily: '"JetBrains Mono", monospace',
                              fontWeight: 700
                            }}
                          >
                            CVE {finding.cve_id}
                          </span>
                        )}
                        {/* Reference CVE */}
                        {finding.ref_cve_id && finding.ref_cve_id !== finding.cve_id && (
                          <span
                            title={`Nearest MITRE/NVD Reference CVE: ${finding.ref_cve_id}`}
                            style={{
                              fontSize: '0.68rem',
                              background: 'rgba(245, 158, 11, 0.15)',
                              border: '1px solid rgba(245, 158, 11, 0.4)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              color: '#fbbf24',
                              fontFamily: '"JetBrains Mono", monospace',
                              fontWeight: 600
                            }}
                          >
                            REF {finding.ref_cve_id}
                          </span>
                        )}
                        {finding.status === 'fixed' && (
                          <span style={{ fontSize: '0.68rem', background: 'rgba(0, 240, 255, 0.2)', color: '#00f0ff', padding: '2px 8px', borderRadius: '4px', boxShadow: '0 0 8px #00f0ff' }}>
                            REMEDIATED
                          </span>
                        )}
                      </div>
                      <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.82rem', color: '#38bdf8' }}>
                        {finding.path}:{finding.start_line}-{finding.end_line}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.74rem', color: '#00f0ff', fontFamily: 'Orbitron, monospace', opacity: 0.8 }}>
                      {finding.id}
                    </span>
                  </div>

                  <div style={{ padding: '12px 16px', fontSize: '0.86rem', color: '#bae6fd', lineHeight: 1.5 }}>
                    {finding.content}
                  </div>

                  {/* Vulnerable Code & Solution Presentation */}
                  <div style={{ margin: '0 16px 12px 16px', borderRadius: '6px', border: '1px solid rgba(0, 240, 255, 0.2)', background: '#010309', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', overflow: 'hidden' }}>
                    <div style={{ padding: '6px 12px', background: 'rgba(0, 240, 255, 0.05)', color: '#64748b', borderBottom: '1px solid rgba(0, 240, 255, 0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Code2 size={13} color="#00f0ff" />
                        <span style={{ color: '#94a3b8' }}>Target: Line {finding.start_line}{finding.end_line !== finding.start_line ? `-${finding.end_line}` : ''}</span>
                      </div>
                      
                      {finding.suggestion_code && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(0, 0, 0, 0.4)', borderRadius: '4px', padding: '2px' }}>
                          <button
                            onClick={() => setCardViewModes(prev => ({ ...prev, [finding.id]: 'stacked' }))}
                            style={{
                              padding: '2px 8px',
                              borderRadius: '3px',
                              border: 'none',
                              background: (cardViewModes[finding.id] || 'stacked') === 'stacked' ? 'rgba(0, 240, 255, 0.2)' : 'transparent',
                              color: (cardViewModes[finding.id] || 'stacked') === 'stacked' ? '#00f0ff' : '#64748b',
                              fontSize: '0.68rem',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                            <Split size={10} /> Side-by-Side
                          </button>
                          <button
                            onClick={() => setCardViewModes(prev => ({ ...prev, [finding.id]: 'diff' }))}
                            style={{
                              padding: '2px 8px',
                              borderRadius: '3px',
                              border: 'none',
                              background: cardViewModes[finding.id] === 'diff' ? 'rgba(0, 240, 255, 0.2)' : 'transparent',
                              color: cardViewModes[finding.id] === 'diff' ? '#00f0ff' : '#64748b',
                              fontSize: '0.68rem',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                            <Layers size={10} /> Unified Diff
                          </button>
                        </div>
                      )}
                    </div>

                    {(cardViewModes[finding.id] || 'stacked') === 'diff' && finding.suggestion_code ? (
                      <div>
                        {finding.existing_code && (
                          <div style={{ padding: '8px 12px', background: 'rgba(239, 68, 68, 0.08)', color: '#fca5a5', borderLeft: '3px solid #ef4444', whiteSpace: 'pre-wrap' }}>
                            <span style={{ userSelect: 'none', marginRight: '8px', color: '#ef4444', fontWeight: 'bold' }}>-</span>
                            {finding.existing_code}
                          </div>
                        )}
                        <div style={{ padding: '8px 12px', background: 'rgba(0, 240, 255, 0.1)', color: '#00f0ff', borderLeft: '3px solid #00f0ff', whiteSpace: 'pre-wrap', boxShadow: 'inset 0 0 10px rgba(0, 240, 255, 0.05)' }}>
                          <span style={{ userSelect: 'none', marginRight: '8px', color: '#00f0ff', fontWeight: 'bold' }}>+</span>
                          {finding.suggestion_code}
                        </div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ borderBottom: finding.suggestion_code ? '1px solid rgba(0, 240, 255, 0.1)' : 'none' }}>
                          <div style={{ padding: '5px 12px', background: 'rgba(239, 68, 68, 0.12)', borderBottom: '1px solid rgba(239, 68, 68, 0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.7rem', color: '#f87171', fontWeight: 700, letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                              ⚠️ VULNERABLE CODE (Line {finding.start_line})
                            </span>
                            <button
                              onClick={() => copyToClipboard(finding.existing_code || '', `vuln-${finding.id}`)}
                              style={{ padding: '2px 6px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '3px', color: '#fca5a5', fontSize: '0.66rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}>
                              {copiedSnippet === `vuln-${finding.id}` ? <Check size={11} color="#4ade80" /> : <Copy size={11} />}
                              {copiedSnippet === `vuln-${finding.id}` ? 'COPIED' : 'COPY VULNERABLE CODE'}
                            </button>
                          </div>
                          <div style={{ padding: '10px 12px', background: 'rgba(15, 7, 10, 0.85)', color: '#fecaca', borderLeft: '3px solid #ef4444', whiteSpace: 'pre-wrap', overflowX: 'auto', lineHeight: 1.4 }}>
                            {finding.existing_code || `// Vulnerable code at ${finding.path}:${finding.start_line}`}
                          </div>
                        </div>

                        {finding.suggestion_code && (
                          <div>
                            <div style={{ padding: '5px 12px', background: 'rgba(0, 240, 255, 0.08)', borderBottom: '1px solid rgba(0, 240, 255, 0.15)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontSize: '0.7rem', color: '#38bdf8', fontWeight: 700, letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                ✨ SUGGESTED PATCH / REMEDIATION
                              </span>
                              <button
                                onClick={() => copyToClipboard(finding.suggestion_code || '', `patch-${finding.id}`)}
                                style={{ padding: '2px 6px', background: 'rgba(0, 240, 255, 0.15)', border: '1px solid rgba(0, 240, 255, 0.3)', borderRadius: '3px', color: '#38bdf8', fontSize: '0.66rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                {copiedSnippet === `patch-${finding.id}` ? <Check size={11} color="#4ade80" /> : <Copy size={11} />}
                                {copiedSnippet === `patch-${finding.id}` ? 'COPIED' : 'COPY PATCH'}
                              </button>
                            </div>
                            <div style={{ padding: '10px 12px', background: 'rgba(2, 18, 23, 0.85)', color: '#67e8f9', borderLeft: '3px solid #00f0ff', whiteSpace: 'pre-wrap', overflowX: 'auto', lineHeight: 1.4 }}>
                              {finding.suggestion_code}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div style={{ padding: '10px 16px', background: '#020612', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(0, 240, 255, 0.1)' }}>
                    <button
                      onClick={() => handleDiscussFinding(finding)}
                      disabled={chatLoading}
                      style={{
                        padding: '6px 12px',
                        borderRadius: '6px',
                        border: '1px solid rgba(0, 240, 255, 0.3)',
                        background: 'rgba(0, 240, 255, 0.08)',
                        color: '#00f0ff',
                        cursor: chatLoading ? 'not-allowed' : 'pointer',
                        fontSize: '0.78rem',
                        fontFamily: 'Orbitron, sans-serif',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        opacity: chatLoading ? 0.6 : 1
                      }}>
                      <MessageSquare size={13} />
                      DISCUSS IN CHAT
                    </button>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <button
                        onClick={() => {
                          const cliCmd = `/fix ${finding.id}`;
                          navigator.clipboard.writeText(cliCmd);
                          setCopiedSnippet(finding.id + '-fixcmd');
                          setTimeout(() => setCopiedSnippet(null), 2000);
                        }}
                        title="Copy CLI /fix command to remediate in qbitcode terminal"
                        style={{
                          padding: '6px 12px',
                          borderRadius: '6px',
                          border: '1px solid rgba(0, 240, 255, 0.3)',
                          background: 'rgba(0, 112, 243, 0.12)',
                          color: '#38bdf8',
                          cursor: 'pointer',
                          fontSize: '0.74rem',
                          fontFamily: 'Orbitron, sans-serif',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}>
                        {copiedSnippet === finding.id + '-fixcmd' ? <Check size={12} color="#00f0ff" /> : <Terminal size={12} />}
                        {copiedSnippet === finding.id + '-fixcmd' ? 'COPIED /FIX' : 'COPY /FIX CMD'}
                      </button>

                      <div style={{
                        padding: '4px 8px',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.04)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        fontSize: '0.68rem',
                        color: '#64748b',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        <Shield size={10} color="#38bdf8" />
                        READ-ONLY
                      </div>
                    </div>
                  </div>
                </div>
              );

              // 1. FLAT LIST VIEW
              if (!groupByFolder) {
                return filteredFindings.map(renderFindingCard);
              }

              // 2. UNIFIED VS-CODE WORKSPACE FILE EXPLORER & CODE VIEWER
              // Filter findings based on selectedTreePath (file or directory)
              const visibleFindings = filteredFindings.filter(f => {
                if (!selectedTreePath) return true;
                const p = (f.path || '').replace(/\\/g, '/');
                return p === selectedTreePath || p.startsWith(selectedTreePath + '/');
              });

              return (
                <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '18px', alignItems: 'start' }}>
                  {/* UNIFIED VS-CODE WORKSPACE EXPLORER (LEFT PANE) */}
                  <UnifiedFileExplorer
                    currentScope={scanPath}
                    onSelectScope={(path) => {
                      setScanPath(path);
                      setSelectedTreePath(path);
                    }}
                    onSelectFinding={(f) => {
                      setSelectedFinding(f);
                      setSelectedTreePath(f.path);
                    }}
                    findings={findings}
                    activeScanPath={scanProgress.currentSubrepo}
                    isScanning={loading}
                    onRunScan={(path) => handleRunScan(path)}
                    onRunFastScan={(path) => handleDirectFastScan(path)}
                    onRunSuperFastScan={(path) => handleDirectSuperFastScan(path)}
                    superFastHours={superFastHours}
                    onSuperFastHoursChange={(h) => setSuperFastHours(h)}
                  />

                  {/* VULNERABILITY CODE & FINDINGS LIST (RIGHT CONTENT PANE) */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', minWidth: 0 }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 14px',
                      background: 'rgba(0, 240, 255, 0.05)',
                      borderRadius: '6px',
                      border: '1px solid rgba(0, 240, 255, 0.2)',
                      flexWrap: 'wrap',
                      gap: '8px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FolderOpen size={15} color="#00f0ff" />
                        <span style={{ fontSize: '0.82rem', fontWeight: 700, fontFamily: '"JetBrains Mono", monospace', color: '#00f0ff' }}>
                          {selectedTreePath ? selectedTreePath : 'Entire Workspace (All Defect Files)'}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontSize: '0.74rem', color: '#38bdf8', fontFamily: '"JetBrains Mono", monospace' }}>
                          Showing {visibleFindings.length} target defect(s)
                        </span>
                        {selectedTreePath && (
                          <button
                            onClick={() => {
                              setSelectedTreePath('');
                              setScanPath('');
                            }}
                            style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(255, 255, 255, 0.05)',
                              border: '1px solid rgba(255, 255, 255, 0.15)',
                              color: '#94a3b8',
                              fontSize: '0.68rem',
                              cursor: 'pointer',
                              fontFamily: 'Orbitron, sans-serif'
                            }}>
                            CLEAR FILTER
                          </button>
                        )}
                      </div>
                    </div>

                    {visibleFindings.length === 0 ? (
                      (() => {
                        const isSelectedUnscanned = selectedTreePath && findings.length > 0 && !findings.some(f => {
                          const p = (f.path || '').replace(/\\/g, '/');
                          return p === selectedTreePath || p.startsWith(selectedTreePath + '/');
                        }) && (!scanProgress.currentSubrepo || !scanProgress.currentSubrepo.includes(selectedTreePath));

                        const isActivelyScanning = scanProgress.currentSubrepo && selectedTreePath && scanProgress.currentSubrepo.includes(selectedTreePath);

                        if (isActivelyScanning) {
                          return (
                            <div style={{
                              padding: '50px 20px',
                              textAlign: 'center',
                              color: '#38bdf8',
                              background: 'rgba(2, 6, 18, 0.7)',
                              border: '1px solid rgba(0, 240, 255, 0.4)',
                              borderRadius: '8px',
                              boxShadow: '0 0 20px rgba(0, 240, 255, 0.15)'
                            }}>
                              <RefreshCw size={36} className="animate-spin" style={{ margin: '0 auto 12px auto', color: '#00f0ff' }} />
                              <p style={{ fontSize: '0.95rem', fontFamily: 'Orbitron, sans-serif', color: '#00f0ff', fontWeight: 700 }}>
                                ACTIVE AI SCANNING IN PROGRESS...
                              </p>
                              <p style={{ fontSize: '0.8rem', marginTop: '6px', color: '#94a3b8' }}>
                                Target: {selectedTreePath}
                              </p>
                            </div>
                          );
                        }

                        if (isSelectedUnscanned) {
                          return (
                            <div style={{
                              padding: '50px 20px',
                              textAlign: 'center',
                              color: '#fbbf24',
                              background: 'rgba(2, 6, 18, 0.7)',
                              border: '1px dashed rgba(245, 158, 11, 0.4)',
                              borderRadius: '8px'
                            }}>
                              <AlertCircle size={36} style={{ margin: '0 auto 12px auto', color: '#fbbf24', opacity: 0.9 }} />
                              <p style={{ fontSize: '0.95rem', fontFamily: 'Orbitron, sans-serif', color: '#fbbf24', fontWeight: 700 }}>
                                TARGET PENDING SCAN (NOT AUDITED YET)
                              </p>
                              <p style={{ fontSize: '0.82rem', marginTop: '6px', color: '#cbd5e1' }}>
                                Target: <strong>{selectedTreePath}</strong> is queued in the batch runner.
                              </p>
                              <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'center', gap: '8px' }}>
                                <button
                                  onClick={() => handleDirectFastScan(selectedTreePath)}
                                  disabled={loading}
                                  style={{
                                    padding: '7px 14px',
                                    borderRadius: '5px',
                                    border: '1px solid #ffb800',
                                    background: 'rgba(255, 184, 0, 0.2)',
                                    color: '#ffb800',
                                    fontSize: '0.74rem',
                                    fontFamily: 'Orbitron, sans-serif',
                                    cursor: 'pointer',
                                    fontWeight: 700
                                  }}>
                                  ⚡ SCAN THIS TARGET NOW
                                </button>
                              </div>
                            </div>
                          );
                        }

                        return (
                          <div style={{
                            padding: '40px 20px',
                            textAlign: 'center',
                            color: '#64748b',
                            background: 'rgba(2, 6, 18, 0.6)',
                            border: '1px dashed rgba(0, 240, 255, 0.2)',
                            borderRadius: '8px'
                          }}>
                            <CheckCircle2 size={32} style={{ margin: '0 auto 8px auto', color: filteredFindings.length === 0 ? '#38bdf8' : '#10b981', opacity: 0.8 }} />
                            <p style={{ fontSize: '0.88rem', fontFamily: 'Orbitron, sans-serif', color: '#e0f2fe' }}>
                              {filteredFindings.length === 0 ? '0 TARGET DEFECTS IDENTIFIED' : 'VERIFIED CLEAN: 0 VULNERABILITIES DETECTED'}
                            </p>
                            <p style={{ fontSize: '0.75rem', marginTop: '4px', color: '#64748b' }}>
                              {filteredFindings.length === 0 ? 'Click any folder or file on the left, or click FAST, SUPER, or SCAN to begin.' : `Audited via Content Deduplication & AI Inspection (${selectedTreePath || 'Selected Scope'})`}
                            </p>
                          </div>
                        );
                      })()
                    ) : (
                      visibleFindings.map(renderFindingCard)
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        </section>

        {/* Right Column: Qbit AI Chat Studio (Sidebar) */}
        <aside className="sidebar-advisor" style={{
          width: '380px',
          maxWidth: '380px',
          flexShrink: 0,
          display: 'flex',
          flexDirection: 'column',
          background: 'rgba(3, 8, 22, 0.95)',
          border: '1px solid rgba(0, 240, 255, 0.25)',
          boxShadow: '0 0 20px rgba(0, 112, 243, 0.15)',
          borderRadius: '10px',
          overflow: 'hidden',
          height: 'calc(100vh - 200px)',
          position: 'sticky',
          top: '85px'
        }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid rgba(0, 240, 255, 0.2)', background: 'rgba(0, 240, 255, 0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00f0ff', boxShadow: '0 0 8px #00f0ff' }} />
              <span style={{ fontSize: '0.9rem', fontWeight: 700, fontFamily: 'Orbitron, sans-serif', color: '#00f0ff' }}>QBIT AI ADVISOR</span>
              <span style={{ fontSize: '0.65rem', padding: '2px 6px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.3)', color: '#38bdf8', letterSpacing: '0.5px' }}>
                READ-ONLY
              </span>
            </div>
            {selectedFinding && (
              <span style={{ fontSize: '0.72rem', color: '#38bdf8', fontFamily: '"JetBrains Mono", monospace' }}>
                TARGET: {selectedFinding.id}
              </span>
            )}
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {messages.map((m, idx) => (
              <div key={idx} style={{
                alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '85%',
                padding: '12px 16px',
                borderRadius: '8px',
                background: m.role === 'user' ? 'rgba(0, 112, 243, 0.3)' : 'rgba(0, 240, 255, 0.06)',
                border: m.role === 'user' ? '1px solid #0070f3' : '1px solid rgba(0, 240, 255, 0.2)',
                boxShadow: m.role === 'user' ? '0 0 10px rgba(0, 112, 243, 0.3)' : 'none',
                color: '#fff',
                fontSize: '0.84rem',
                lineHeight: 1.5,
                whiteSpace: 'pre-wrap',
                fontFamily: '"JetBrains Mono", monospace'
              }}>
                {m.content}
              </div>
            ))}
            {chatLoading && (
              <div style={{ alignSelf: 'flex-start', color: '#00f0ff', fontSize: '0.8rem', fontStyle: 'italic', fontFamily: 'Orbitron, sans-serif' }}>
                GENERATING REASONING TOKENS...
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          <form onSubmit={handleSendMessage} style={{ padding: '12px', borderTop: '1px solid rgba(0, 240, 255, 0.2)', display: 'flex', gap: '8px', background: '#020612' }}>
            <input
              type="text"
              placeholder={selectedFinding ? `Question regarding ${selectedFinding.id}...` : "Command or query security model..."}
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              style={{
                flex: 1,
                padding: '10px 14px',
                borderRadius: '6px',
                background: 'rgba(0, 0, 0, 0.6)',
                border: '1px solid rgba(0, 240, 255, 0.3)',
                boxShadow: 'inset 0 0 8px rgba(0, 240, 255, 0.1)',
                color: '#fff',
                fontSize: '0.85rem',
                fontFamily: '"JetBrains Mono", monospace'
              }}
            />
            <button
              type="submit"
              disabled={chatLoading}
              style={{
                padding: '0 16px',
                borderRadius: '6px',
                border: 'none',
                background: 'linear-gradient(135deg, #0070f3, #00f0ff)',
                color: '#000',
                fontWeight: 'bold',
                cursor: 'pointer',
                boxShadow: '0 0 12px rgba(0, 240, 255, 0.4)'
              }}>
              <Send size={15} />
            </button>
          </form>
        </aside>
      </main>
      )}

      {/* Cyber Multi-Tab Terminal Console */}
      <CyberTerminalTabs
        logs={logs}
        metrics={metrics}
        isOpen={terminalOpen}
        onClose={() => setTerminalOpen(false)}
      />

      {/* FULL SCREEN CYBERPUNK SYNTHESIZER FIXING / LOADING SCREEN OVERLAY */}
      {synthesizing && (
        <div style={{
          position: 'fixed',
          inset: 0,
          zIndex: 99999,
          background: 'rgba(0, 3, 14, 0.90)',
          backdropFilter: 'blur(16px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '20px'
        }}>
          <div style={{
            width: '620px',
            maxWidth: '94vw',
            background: 'linear-gradient(180deg, #030a21 0%, #01040f 100%)',
            border: '1px solid rgba(0, 240, 255, 0.5)',
            borderRadius: '14px',
            boxShadow: '0 0 60px rgba(0, 240, 255, 0.35), inset 0 0 30px rgba(0, 112, 243, 0.2)',
            overflow: 'hidden',
            position: 'relative'
          }}>
            {/* Top scanning cyber line */}
            <div style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: '3px',
              background: 'linear-gradient(90deg, transparent, #00f0ff, transparent)',
              animation: 'scanline-slide 2.5s infinite linear'
            }} />

            {/* Modal Body */}
            <div style={{ padding: '34px 28px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
              
              {/* Animated Cyber Radar Core */}
              <div style={{ position: 'relative', width: '92px', height: '92px', marginBottom: '22px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {/* Outer spinning ring */}
                <div 
                  className="spin-ring"
                  style={{
                    position: 'absolute',
                    inset: 0,
                    borderRadius: '50%',
                    border: '2px dashed rgba(0, 240, 255, 0.6)',
                    boxShadow: '0 0 20px rgba(0, 240, 255, 0.4)'
                  }} 
                />
                {/* Reverse inner spinning ring */}
                <div 
                  className="reverse-spin-ring"
                  style={{
                    position: 'absolute',
                    inset: '10px',
                    borderRadius: '50%',
                    border: '2px dotted rgba(0, 112, 243, 0.8)'
                  }} 
                />
                {/* Pulsing center icon */}
                <div 
                  className="radar-ring"
                  style={{
                    width: '54px',
                    height: '54px',
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, #0070f3, #00f0ff)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 0 25px #00f0ff'
                  }}>
                  {synthesisProgress.completed ? (
                    <Check size={28} color="#000" strokeWidth={3} />
                  ) : (
                    <Zap size={26} color="#000" strokeWidth={2.5} />
                  )}
                </div>
              </div>

              {/* Title & Status */}
              <div style={{
                fontSize: '0.72rem',
                letterSpacing: '2px',
                fontFamily: 'Orbitron, sans-serif',
                color: '#38bdf8',
                marginBottom: '6px',
                fontWeight: 700
              }}>
                AUTONOMOUS REMEDIATION ENGINE ACTIVE
              </div>
              <h2 style={{
                margin: '0 0 8px 0',
                fontSize: '1.45rem',
                fontWeight: 800,
                color: '#ffffff',
                fontFamily: 'Orbitron, sans-serif',
                textShadow: '0 0 20px rgba(0, 240, 255, 0.6)'
              }}>
                {synthesisProgress.completed ? 'ALL PATCHES SYNTHESIZED!' : 'SYNTHESIZING VERIFIED PATCHES'}
              </h2>
              <p style={{
                margin: '0 0 24px 0',
                fontSize: '0.82rem',
                color: '#94a3b8',
                maxWidth: '480px',
                lineHeight: 1.5
              }}>
                Generating concrete, production-ready code fixes via local Qbit AI (Qwen2.5-Coder-14B). All empty cells and comments are being eliminated.
              </p>

              {/* Progress Bar Container */}
              <div style={{ width: '100%', marginBottom: '16px' }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '8px',
                  fontSize: '0.75rem',
                  fontFamily: 'Orbitron, sans-serif',
                  color: '#00f0ff'
                }}>
                  <span>PROGRESS</span>
                  <span>{synthesisProgress.current} / {synthesisProgress.total} ({synthesisProgress.percent}%)</span>
                </div>
                <div style={{
                  width: '100%',
                  height: '14px',
                  background: 'rgba(0, 0, 0, 0.7)',
                  borderRadius: '7px',
                  border: '1px solid rgba(0, 240, 255, 0.3)',
                  overflow: 'hidden',
                  position: 'relative'
                }}>
                  <div 
                    className="shimmer-progress"
                    style={{
                      height: '100%',
                      width: `${Math.max(5, synthesisProgress.percent)}%`,
                      borderRadius: '7px',
                      transition: 'width 0.3s ease-out',
                      boxShadow: '0 0 15px #00f0ff'
                    }}
                  />
                </div>
              </div>

              {/* Active Target Box */}
              <div style={{
                width: '100%',
                background: 'rgba(0, 240, 255, 0.04)',
                border: '1px solid rgba(0, 240, 255, 0.2)',
                borderRadius: '8px',
                padding: '12px 16px',
                textAlign: 'left',
                marginBottom: '20px',
                boxShadow: 'inset 0 0 15px rgba(0, 240, 255, 0.05)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '0.68rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif' }}>TARGET COMPONENT</span>
                  <span style={{ fontSize: '0.7rem', color: '#fbbf24', fontWeight: 600 }}>
                    {synthesisProgress.currentCategory || 'Remediation'}
                  </span>
                </div>
                <div style={{
                  fontSize: '0.82rem',
                  fontFamily: '"JetBrains Mono", monospace',
                  color: '#e0f2fe',
                  wordBreak: 'break-all',
                  marginBottom: '4px'
                }}>
                  📄 {synthesisProgress.currentPath || 'Analyzing codebase findings...'}
                  {synthesisProgress.currentLine ? ` : Line ${synthesisProgress.currentLine}` : ''}
                </div>
                <div style={{
                  fontSize: '0.72rem',
                  color: '#38bdf8',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>
                  › {synthesisProgress.statusText || 'Querying local vLLM for syntax & memory bounds fix...'}
                </div>
              </div>

              {/* Security lock note */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '0.74rem',
                color: '#64748b',
                fontFamily: 'Orbitron, sans-serif'
              }}>
                <Shield size={13} color="#00f0ff" />
                <span>USER INTERACTION LOCKED • PLEASE WAIT FOR SYNTHESIS TO FINISH</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* FASTSCAN EXEMPTIONS MODAL */}
      {fastScanOpen && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(2, 6, 23, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '24px'
        }}>
          <div style={{
            width: '100%',
            maxWidth: '920px',
            maxHeight: '88vh',
            background: 'linear-gradient(145deg, rgba(8, 15, 35, 0.98), rgba(3, 8, 22, 0.98))',
            borderRadius: '14px',
            border: '1px solid rgba(255, 184, 0, 0.4)',
            boxShadow: '0 0 40px rgba(255, 184, 0, 0.25), 0 0 80px rgba(0, 0, 0, 0.9)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '18px 24px',
              borderBottom: '1px solid rgba(255, 184, 0, 0.2)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'rgba(255, 184, 0, 0.05)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Zap size={22} color="#ffb800" style={{ filter: 'drop-shadow(0 0 8px #ffb800)' }} />
                <div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#ffb800', fontFamily: 'Orbitron, sans-serif' }}>
                    FASTSCAN: WORKSPACE EXEMPTIONS COCKPIT
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontFamily: '"JetBrains Mono", monospace' }}>
                    Target: {fastScanData?.targetDir || scanPath || 'Entire Workspace'}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setFastScanOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '1.2rem',
                  cursor: 'pointer',
                  padding: '4px 8px'
                }}>
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {fastScanLoading ? (
                <div style={{ textAlign: 'center', padding: '48px 0', color: '#ffb800', fontFamily: 'Orbitron, sans-serif' }}>
                  <RefreshCw className="animate-spin" size={32} style={{ margin: '0 auto 12px' }} />
                  <div>TRAVERSING DIRECTORY & DISCOVERING EXEMPTIONS...</div>
                </div>
              ) : (
                <>
                  {/* Summary Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
                    <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(255, 184, 0, 0.3)', borderRadius: '8px', padding: '12px 14px' }}>
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'Orbitron, sans-serif' }}>EXEMPT FOLDERS</div>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffb800' }}>
                        {fastScanData?.summary?.exemptFoldersCount ?? 0}
                      </div>
                    </div>

                    <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(0, 240, 255, 0.3)', borderRadius: '8px', padding: '12px 14px' }}>
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'Orbitron, sans-serif' }}>EXEMPT FILES</div>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#00f0ff' }}>
                        {fastScanData?.summary?.exemptFilesCount ?? 0}
                      </div>
                    </div>

                    <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '12px 14px' }}>
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'Orbitron, sans-serif' }}>CODE IN SCOPE</div>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981' }}>
                        {fastScanData?.summary?.sourceFilesCount ?? 0}
                      </div>
                    </div>

                    <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '8px', padding: '12px 14px' }}>
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'Orbitron, sans-serif' }}>SPEEDUP</div>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f59e0b', textShadow: '0 0 10px rgba(245, 158, 11, 0.5)' }}>
                        {fastScanData?.summary?.estimatedSpeedup ?? '80%'}
                      </div>
                    </div>
                  </div>

                  {/* Tabs */}
                  <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '8px' }}>
                    <button
                      onClick={() => setFastScanTab('folders')}
                      style={{
                        padding: '6px 14px',
                        borderRadius: '6px',
                        border: 'none',
                        background: fastScanTab === 'folders' ? 'rgba(255, 184, 0, 0.2)' : 'transparent',
                        color: fastScanTab === 'folders' ? '#ffb800' : '#94a3b8',
                        fontWeight: 700,
                        fontSize: '0.82rem',
                        cursor: 'pointer'
                      }}>
                      📁 Exempted Folders ({fastScanData?.exemptFolders?.length || 0})
                    </button>
                    <button
                      onClick={() => setFastScanTab('files')}
                      style={{
                        padding: '6px 14px',
                        borderRadius: '6px',
                        border: 'none',
                        background: fastScanTab === 'files' ? 'rgba(0, 240, 255, 0.2)' : 'transparent',
                        color: fastScanTab === 'files' ? '#00f0ff' : '#94a3b8',
                        fontWeight: 700,
                        fontSize: '0.82rem',
                        cursor: 'pointer'
                      }}>
                      📄 Exempted Files ({fastScanData?.exemptFiles?.length || 0})
                    </button>
                  </div>

                  {/* Item List */}
                  <div style={{ maxHeight: '340px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {fastScanTab === 'folders' && (
                      fastScanData?.exemptFolders?.length > 0 ? (
                        fastScanData.exemptFolders.map((f: any, idx: number) => (
                          <div key={idx} style={{
                            padding: '10px 14px',
                            borderRadius: '6px',
                            background: 'rgba(15, 23, 42, 0.6)',
                            border: '1px solid rgba(255, 184, 0, 0.15)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '12px'
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: '4px',
                                fontSize: '0.68rem',
                                fontWeight: 800,
                                background: 'rgba(255, 184, 0, 0.15)',
                                color: '#ffb800',
                                fontFamily: 'Orbitron, sans-serif'
                              }}>
                                {f.category}
                              </span>
                              <span style={{ color: '#f1f5f9', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.84rem' }}>
                                📁 {f.relPath}/
                              </span>
                            </div>
                            <span style={{ color: '#64748b', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                              {f.reason} {f.fileCount ? `(${f.fileCount} items)` : ''}
                            </span>
                          </div>
                        ))
                      ) : (
                        <div style={{ color: '#64748b', textAlign: 'center', padding: '24px' }}>No exempt folders found in target.</div>
                      )
                    )}

                    {fastScanTab === 'files' && (
                      fastScanData?.exemptFiles?.length > 0 ? (
                        fastScanData.exemptFiles.slice(0, 100).map((file: any, idx: number) => (
                          <div key={idx} style={{
                            padding: '10px 14px',
                            borderRadius: '6px',
                            background: 'rgba(15, 23, 42, 0.6)',
                            border: '1px solid rgba(0, 240, 255, 0.15)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '12px'
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
                              <span style={{
                                padding: '2px 6px',
                                borderRadius: '4px',
                                fontSize: '0.68rem',
                                fontWeight: 800,
                                background: 'rgba(0, 240, 255, 0.15)',
                                color: '#00f0ff',
                                fontFamily: 'Orbitron, sans-serif'
                              }}>
                                {file.category}
                              </span>
                              <span style={{ color: '#f1f5f9', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.84rem' }}>
                                📄 {file.relPath}
                              </span>
                            </div>
                            <span style={{ color: '#64748b', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                              {file.reason}
                            </span>
                          </div>
                        ))
                      ) : (
                        <div style={{ color: '#64748b', textAlign: 'center', padding: '24px' }}>No exempt files found in target.</div>
                      )
                    )}
                  </div>

                  <div style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={14} />
                    <span>Exemptions are automatically saved to <code>.qbit/scan_exemptions.json</code> and applied to all scans.</span>
                  </div>
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '14px 24px',
              borderTop: '1px solid rgba(255, 184, 0, 0.2)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '10px',
              background: 'rgba(255, 184, 0, 0.03)'
            }}>
              <button
                onClick={() => setFastScanOpen(false)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  background: 'rgba(255, 255, 255, 0.08)',
                  color: '#94a3b8',
                  border: 'none',
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontSize: '0.82rem'
                }}>
                CLOSE
              </button>
              <button
                onClick={() => {
                  setFastScanOpen(false);
                  handleRunScan(scanPath);
                }}
                disabled={loading}
                style={{
                  padding: '8px 20px',
                  borderRadius: '6px',
                  border: 'none',
                  background: 'linear-gradient(135deg, #ffb800, #ff5500)',
                  color: '#000',
                  cursor: 'pointer',
                  fontWeight: 800,
                  fontSize: '0.85rem',
                  fontFamily: 'Orbitron, sans-serif',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  boxShadow: '0 0 20px rgba(255, 184, 0, 0.5)'
                }}>
                <Zap size={14} />
                LAUNCH ACCELERATED SCAN
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
