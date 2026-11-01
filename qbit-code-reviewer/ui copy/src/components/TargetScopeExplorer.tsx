import React, { useState, useEffect, useRef } from 'react';
import { 
  Folder, 
  FolderOpen, 
  FileCode, 
  Search, 
  ChevronRight, 
  ChevronDown, 
  X, 
  Target, 
  ArrowRight
} from 'lucide-react';

interface FileItem {
  name: string;
  path: string;
  type: 'directory' | 'file';
}

interface TargetExplorerProps {
  currentScope: string;
  onSelectScope: (path: string) => void;
  onRunScan: (scopePath: string) => void;
  loading: boolean;
}

export function TargetScopeExplorer({
  currentScope,
  onSelectScope,
  onRunScan,
  loading
}: TargetExplorerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [suggestions, setSuggestions] = useState<FileItem[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);

  // Directory tree state
  const [treeItems, setTreeItems] = useState<FileItem[]>([]);
  const [expandedDirs, setExpandedDirs] = useState<Record<string, FileItem[]>>({});

  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Fetch top-level directory contents when opening modal
  useEffect(() => {
    if (isOpen) {
      loadDirectory('');
      if (searchInputRef.current) {
        searchInputRef.current.focus();
      }
    }
  }, [isOpen]);

  // Load directory items from backend
  const loadDirectory = async (dirPath: string) => {
    try {
      const res = await fetch(`/api/files?dir=${encodeURIComponent(dirPath)}`);
      if (res.ok) {
        const data = await res.json();
        if (dirPath === '') {
          setTreeItems(data.items || []);
        } else {
          setExpandedDirs(prev => ({
            ...prev,
            [dirPath]: data.items || []
          }));
        }
      }
    } catch (err) {
      console.error('Failed to load directory:', err);
    }
  };

  // Debounced auto-suggestions for search input
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSuggestions([]);
      return;
    }

    const handler = setTimeout(async () => {
      setSearchLoading(true);
      try {
        const res = await fetch(`/api/files?q=${encodeURIComponent(searchQuery.trim())}`);
        if (res.ok) {
          const data = await res.json();
          setSuggestions(data.results || []);
        }
      } catch (err) {
        console.error('Failed to search files:', err);
      } finally {
        setSearchLoading(false);
      }
    }, 200);

    return () => clearTimeout(handler);
  }, [searchQuery]);

  const toggleExpand = (dirPath: string) => {
    if (expandedDirs[dirPath]) {
      // Collapse
      setExpandedDirs(prev => {
        const next = { ...prev };
        delete next[dirPath];
        return next;
      });
    } else {
      // Expand and load
      loadDirectory(dirPath);
    }
  };

  const selectAndClose = (path: string) => {
    onSelectScope(path);
    setIsOpen(false);
  };

  const handleQuickRun = (path: string, e: React.MouseEvent) => {
    e.stopPropagation();
    onSelectScope(path);
    setIsOpen(false);
    onRunScan(path);
  };

  return (
    <div ref={containerRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      {/* SCOPE TRIGGER / SEARCH INPUT BAR */}
      <div 
        onClick={() => setIsOpen(true)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          background: 'rgba(0, 0, 0, 0.75)',
          border: isOpen ? '1px solid #00f0ff' : '1px solid rgba(0, 240, 255, 0.35)',
          borderRadius: '7px',
          padding: '6px 12px',
          cursor: 'pointer',
          minWidth: '240px',
          maxWidth: '320px',
          boxShadow: isOpen ? '0 0 15px rgba(0, 240, 255, 0.25)' : 'none',
          transition: 'all 0.2s ease'
        }}>
        <Target size={14} style={{ color: currentScope ? '#00f0ff' : '#64748b', flexShrink: 0 }} />
        
        <div style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          <span style={{ fontSize: '0.72rem', color: '#64748b', marginRight: '6px' }}>SCOPE:</span>
          <span style={{
            fontSize: '0.78rem',
            fontFamily: '"JetBrains Mono", monospace',
            color: currentScope ? '#00f0ff' : '#94a3b8',
            fontWeight: currentScope ? 700 : 400
          }}>
            {currentScope || 'Entire Repository (Root)'}
          </span>
        </div>

        {currentScope && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onSelectScope('');
            }}
            title="Reset to whole repo"
            style={{
              background: 'transparent',
              border: 'none',
              color: '#64748b',
              cursor: 'pointer',
              padding: '2px',
              display: 'flex',
              alignItems: 'center'
            }}>
            <X size={12} />
          </button>
        )}

        <ChevronDown size={14} style={{ color: '#00f0ff', opacity: 0.8, transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
      </div>

      {/* DROPDOWN FILE EXPLORER MODAL */}
      {isOpen && (
        <div style={{
          position: 'absolute',
          top: '46px',
          right: 0,
          width: '500px',
          maxHeight: '480px',
          background: 'rgba(3, 8, 22, 0.98)',
          border: '1px solid rgba(0, 240, 255, 0.4)',
          borderRadius: '10px',
          boxShadow: '0 12px 35px rgba(0, 0, 0, 0.9), 0 0 25px rgba(0, 240, 255, 0.2)',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          backdropFilter: 'blur(20px)',
          animation: 'fadeIn 0.15s ease-out'
        }}>
          {/* SEARCH BAR & AUTO-SUGGESTION INPUT */}
          <div style={{
            padding: '12px 14px',
            borderBottom: '1px solid rgba(0, 240, 255, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            background: 'rgba(0, 240, 255, 0.03)'
          }}>
            <Search size={16} style={{ color: '#00f0ff' }} />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search files or folders in workspace..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#e0f2fe',
                fontSize: '0.82rem',
                fontFamily: '"JetBrains Mono", monospace'
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>
                <X size={14} />
              </button>
            )}
            {searchLoading && (
              <span style={{ fontSize: '0.72rem', color: '#00f0ff', fontFamily: 'Orbitron, sans-serif' }}>SEARCHING...</span>
            )}
          </div>

          {/* MAIN BODY: TREE / SUGGESTIONS / PRESETS */}
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '420px', padding: '10px' }}>
            
            {/* If searching: show auto-suggestions */}
            {searchQuery.trim() ? (
              <div>
                <div style={{ padding: '6px 10px', fontSize: '0.7rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif', letterSpacing: '0.08em' }}>
                  MATCHING REPOSITORY TARGETS ({suggestions.length})
                </div>
                {suggestions.length === 0 && !searchLoading ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '0.8rem' }}>
                    No matching files or directories found for "{searchQuery}"
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    {suggestions.map((item) => (
                      <div
                        key={item.path}
                        onClick={() => selectAndClose(item.path)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '7px 12px',
                          borderRadius: '6px',
                          background: currentScope === item.path ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 240, 255, 0.02)',
                          border: currentScope === item.path ? '1px solid rgba(0, 240, 255, 0.4)' : '1px solid transparent',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease'
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0, 240, 255, 0.1)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = currentScope === item.path ? 'rgba(0, 240, 255, 0.15)' : 'rgba(0, 240, 255, 0.02)'}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', overflow: 'hidden' }}>
                          {item.type === 'directory' ? (
                            <Folder size={15} style={{ color: '#00f0ff', flexShrink: 0 }} />
                          ) : (
                            <FileCode size={15} style={{ color: '#38bdf8', flexShrink: 0 }} />
                          )}
                          <div style={{ overflow: 'hidden' }}>
                            <div style={{ fontSize: '0.8rem', color: '#e0f2fe', fontFamily: '"JetBrains Mono", monospace' }}>
                              {item.name}
                            </div>
                            <div style={{ fontSize: '0.68rem', color: '#64748b', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                              {item.path}
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <button
                            onClick={(e) => handleQuickRun(item.path, e)}
                            title="Set scope and launch scan immediately"
                            style={{
                              padding: '4px 8px',
                              borderRadius: '4px',
                              background: 'rgba(0, 112, 243, 0.25)',
                              border: '1px solid rgba(0, 240, 255, 0.3)',
                              color: '#00f0ff',
                              fontSize: '0.68rem',
                              fontFamily: 'Orbitron, sans-serif',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                            SCAN NOW <ArrowRight size={10} />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div>
                {/* WORKSPACE DIRECTORY EXPLORER TREE */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 8px', marginBottom: '8px' }}>
                    <span style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'Orbitron, sans-serif', letterSpacing: '0.08em' }}>
                      BROWSE WORKSPACE DIRECTORY
                    </span>
                    <button
                      onClick={() => selectAndClose('')}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#00f0ff',
                        fontSize: '0.7rem',
                        cursor: 'pointer',
                        textDecoration: 'underline'
                      }}>
                      Select Entire Repo (Root)
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                    {treeItems.map((item) => (
                      <TreeNode
                        key={item.path}
                        item={item}
                        expandedDirs={expandedDirs}
                        onToggle={toggleExpand}
                        onSelect={selectAndClose}
                        onQuickRun={handleQuickRun}
                        currentScope={currentScope}
                      />
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* FOOTER ACTIONS */}
          <div style={{
            padding: '10px 14px',
            borderTop: '1px solid rgba(0, 240, 255, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(0, 0, 0, 0.5)'
          }}>
            <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
              Active: <span style={{ color: '#00f0ff', fontFamily: '"JetBrains Mono", monospace' }}>{currentScope || 'Entire Workspace'}</span>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setIsOpen(false)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '5px',
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: '#94a3b8',
                  fontSize: '0.75rem',
                  cursor: 'pointer'
                }}>
                Cancel
              </button>
              <button
                onClick={() => {
                  setIsOpen(false);
                  onRunScan(currentScope);
                }}
                disabled={loading}
                style={{
                  padding: '6px 16px',
                  borderRadius: '5px',
                  background: 'linear-gradient(135deg, #0070f3, #00f0ff)',
                  border: 'none',
                  color: '#000',
                  fontWeight: 800,
                  fontSize: '0.75rem',
                  fontFamily: 'Orbitron, sans-serif',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                RUN SCAN NOW
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Tree Node subcomponent for recursive directory rendering
function TreeNode({
  item,
  expandedDirs,
  onToggle,
  onSelect,
  onQuickRun,
  currentScope,
  depth = 0
}: {
  item: FileItem;
  expandedDirs: Record<string, FileItem[]>;
  onToggle: (path: string) => void;
  onSelect: (path: string) => void;
  onQuickRun: (path: string, e: React.MouseEvent) => void;
  currentScope: string;
  depth?: number;
}) {
  const isExpanded = !!expandedDirs[item.path];
  const children = expandedDirs[item.path] || [];
  const isSelected = currentScope === item.path;

  return (
    <div>
      <div
        onClick={() => {
          if (item.type === 'directory') {
            onToggle(item.path);
          } else {
            onSelect(item.path);
          }
        }}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '5px 8px',
          paddingLeft: `${depth * 16 + 8}px`,
          borderRadius: '4px',
          background: isSelected ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
          border: isSelected ? '1px solid rgba(0, 240, 255, 0.4)' : '1px solid transparent',
          cursor: 'pointer',
          userSelect: 'none'
        }}
        onMouseEnter={(e) => {
          if (!isSelected) e.currentTarget.style.background = 'rgba(0, 240, 255, 0.05)';
        }}
        onMouseLeave={(e) => {
          if (!isSelected) e.currentTarget.style.background = 'transparent';
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
          {item.type === 'directory' ? (
            <span
              onClick={(e) => {
                e.stopPropagation();
                onToggle(item.path);
              }}
              style={{ display: 'flex', alignItems: 'center', color: '#00f0ff' }}>
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              {isExpanded ? <FolderOpen size={15} style={{ marginLeft: '4px', color: '#00f0ff' }} /> : <Folder size={15} style={{ marginLeft: '4px', color: '#38bdf8' }} />}
            </span>
          ) : (
            <FileCode size={14} style={{ color: '#64748b', marginLeft: '18px' }} />
          )}

          <span style={{
            fontSize: '0.78rem',
            color: isSelected ? '#00f0ff' : '#e0f2fe',
            fontFamily: '"JetBrains Mono", monospace',
            fontWeight: isSelected ? 700 : 400
          }}>
            {item.name}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {/* Target select button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onSelect(item.path);
            }}
            title="Set this as target scope"
            style={{
              background: 'transparent',
              border: 'none',
              color: isSelected ? '#00f0ff' : '#64748b',
              fontSize: '0.68rem',
              cursor: 'pointer',
              padding: '2px 6px',
              borderRadius: '3px'
            }}>
            {isSelected ? 'SELECTED' : 'SELECT'}
          </button>

          {/* Quick scan button */}
          <button
            onClick={(e) => onQuickRun(item.path, e)}
            title="Scan this target immediately"
            style={{
              padding: '3px 7px',
              borderRadius: '3px',
              background: 'rgba(0, 112, 243, 0.2)',
              border: '1px solid rgba(0, 240, 255, 0.3)',
              color: '#00f0ff',
              fontSize: '0.65rem',
              fontFamily: 'Orbitron, sans-serif',
              cursor: 'pointer'
            }}>
            SCAN
          </button>
        </div>
      </div>

      {/* Render children if expanded */}
      {isExpanded && children.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1px' }}>
          {children.map(child => (
            <TreeNode
              key={child.path}
              item={child}
              expandedDirs={expandedDirs}
              onToggle={onToggle}
              onSelect={onSelect}
              onQuickRun={onQuickRun}
              currentScope={currentScope}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}
