'use client'

import { useState, useRef, useCallback, useMemo } from 'react'
import { Plus, ArrowLeft, Trash2, Play, Loader2, Sparkles, Eye, RefreshCw } from 'lucide-react'
import { GraphCanvas } from '../GraphCanvas'
import { useDimensions } from '../../hooks'
import { useGraphViews, type GraphView } from '../../hooks/useGraphViews'
import type { GraphData, GraphNode } from '../../types'
import styles from './GraphViews.module.css'

interface GraphViewsProps {
  projectId: string
  userId: string
  modelConfigured: boolean
  is3D: boolean
  showLabels: boolean
  isDark: boolean
}

type Mode = 'list' | 'create' | 'preview'

const EXAMPLE_QUERIES = [
  'All subdomains that resolve to at least 4 IPs',
  'IPs with critical vulnerabilities and their open ports',
  'Technologies with known CVEs and the affected subdomains',
  'All endpoints with injectable parameters',
  'Attack chains that reached exploitation phase',
  'Subdomains with open port 443 and their technologies',
  'All services running on non-standard ports (not 80 or 443)',
]

export function GraphViews({
  projectId,
  userId,
  modelConfigured,
  is3D,
  showLabels,
  isDark,
}: GraphViewsProps) {
  const {
    views,
    isLoading: viewsLoading,
    createView,
    deleteView,
    generateCypher,
    executeCypher,
  } = useGraphViews(projectId)

  const [mode, setMode] = useState<Mode>('list')
  const [nlQuery, setNlQuery] = useState('')
  const [viewName, setViewName] = useState('')
  const [generatedCypher, setGeneratedCypher] = useState<string | null>(null)
  const [previewData, setPreviewData] = useState<GraphData | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [saving, setSaving] = useState(false)
  const [activePreviewView, setActivePreviewView] = useState<GraphView | null>(null)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  const canvasRef = useRef<HTMLDivElement>(null)
  const dimensions = useDimensions(canvasRef)

  const handleGenerate = useCallback(async () => {
    if (!nlQuery.trim()) return
    setGenerating(true)
    setPreviewError(null)
    setGeneratedCypher(null)
    setPreviewData(null)

    const result = await generateCypher(nlQuery.trim(), userId)

    if ('error' in result) {
      setPreviewError(result.error)
      setGenerating(false)
      return
    }

    setGeneratedCypher(result.cypher)
    setViewName(nlQuery.trim().slice(0, 60))

    // Execute the generated cypher for preview
    setPreviewLoading(true)
    const execResult = await executeCypher(result.cypher)
    setGenerating(false)
    setPreviewLoading(false)

    if ('error' in execResult) {
      setPreviewError(execResult.error)
      setPreviewData(null)
    } else {
      setPreviewData({
        nodes: execResult.nodes || [],
        links: execResult.links || [],
        projectId,
      })
    }
  }, [nlQuery, userId, projectId, generateCypher, executeCypher])

  const handleRegenerate = useCallback(async () => {
    setGeneratedCypher(null)
    setPreviewData(null)
    setPreviewError(null)
    await handleGenerate()
  }, [handleGenerate])

  const handleSave = useCallback(async () => {
    if (!generatedCypher || !viewName.trim()) return
    setSaving(true)
    const result = await createView(viewName.trim(), nlQuery.trim(), generatedCypher)
    setSaving(false)
    if (result) {
      setMode('list')
      setNlQuery('')
      setViewName('')
      setGeneratedCypher(null)
      setPreviewData(null)
    }
  }, [generatedCypher, viewName, nlQuery, createView])

  const handlePreviewView = useCallback(async (view: GraphView) => {
    setActivePreviewView(view)
    setMode('preview')
    setPreviewLoading(true)
    setPreviewError(null)
    setPreviewData(null)

    const result = await executeCypher(view.cypherQuery)
    setPreviewLoading(false)

    if ('error' in result) {
      setPreviewError(result.error)
    } else {
      setPreviewData({
        nodes: result.nodes,
        links: result.links,
        projectId,
      })
    }
  }, [projectId, executeCypher])

  const handleDeleteView = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    await deleteView(id)
    if (activePreviewView?.id === id) {
      setMode('list')
      setActivePreviewView(null)
    }
  }, [deleteView, activePreviewView])

  const handleBack = useCallback(() => {
    setMode('list')
    setNlQuery('')
    setViewName('')
    setGeneratedCypher(null)
    setPreviewData(null)
    setPreviewError(null)
    setActivePreviewView(null)
    setSelectedNode(null)
  }, [])

  const handleExampleClick = useCallback((example: string) => {
    setNlQuery(example)
  }, [])

  const nodeCount = useMemo(() => previewData?.nodes.length ?? 0, [previewData])

  // ── LIST MODE ──
  if (mode === 'list') {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <h2 className={styles.title}>Graph Views</h2>
            <span className={styles.subtitle}>
              Saved subgraph queries from natural language
            </span>
          </div>
          <button
            className={styles.createBtn}
            onClick={() => setMode('create')}
            disabled={!modelConfigured}
            title={!modelConfigured ? 'Configure an AI model in project settings to create graph views' : 'Create a new graph view'}
          >
            <Plus size={14} />
            <span>Create New</span>
          </button>
        </div>

        {!modelConfigured && (
          <div className={styles.noLlmBanner}>
            <Sparkles size={14} />
            <span>Configure an AI model in project settings to create graph views with natural language.</span>
          </div>
        )}

        {viewsLoading ? (
          <div className={styles.loadingState}>
            <Loader2 size={16} className={styles.spin} />
            <span>Loading views...</span>
          </div>
        ) : views.length === 0 ? (
          <div className={styles.emptyState}>
            <Eye size={32} className={styles.emptyIcon} />
            <h3>No graph views yet</h3>
            <p>Create filtered perspectives of your reconnaissance graph using natural language queries.</p>
            {modelConfigured && (
              <button className={styles.createBtn} onClick={() => setMode('create')}>
                <Plus size={14} />
                <span>Create Your First View</span>
              </button>
            )}
          </div>
        ) : (
          <div className={styles.viewList}>
            {views.map(view => (
              <div
                key={view.id}
                className={styles.viewCard}
                onClick={() => handlePreviewView(view)}
              >
                <div className={styles.viewInfo}>
                  <span className={styles.viewName}>{view.name}</span>
                  {view.description && (
                    <span className={styles.viewDesc}>{view.description}</span>
                  )}
                  <span className={styles.viewDate}>
                    {new Date(view.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <div className={styles.viewActions}>
                  <button
                    className={styles.iconBtn}
                    onClick={(e) => handleDeleteView(view.id, e)}
                    title="Delete view"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  // ── CREATE MODE ──
  if (mode === 'create') {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <button className={styles.backBtn} onClick={handleBack}>
            <ArrowLeft size={14} />
            <span>Back</span>
          </button>
          <h2 className={styles.title}>Create Graph View</h2>
        </div>

        <div className={styles.createForm}>
          <label className={styles.label}>Describe the subgraph you want to see</label>
          <textarea
            className={styles.textarea}
            placeholder="e.g., All IPs with critical vulnerabilities and their open ports"
            value={nlQuery}
            onChange={e => setNlQuery(e.target.value)}
            rows={3}
            disabled={generating}
          />

          <div className={styles.examples}>
            <span className={styles.examplesLabel}>Examples:</span>
            <div className={styles.exampleChips}>
              {EXAMPLE_QUERIES.map((ex, i) => (
                <button
                  key={i}
                  className={styles.chip}
                  onClick={() => handleExampleClick(ex)}
                  disabled={generating}
                >
                  {ex}
                </button>
              ))}
            </div>
          </div>

          <div className={styles.generateRow}>
            <button
              className={styles.generateBtn}
              onClick={handleGenerate}
              disabled={!nlQuery.trim() || generating}
            >
              {generating ? (
                <>
                  <Loader2 size={14} className={styles.spin} />
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>Generate Cypher</span>
                </>
              )}
            </button>
          </div>

          {previewError && (
            <div className={styles.errorBanner}>
              <span>{previewError}</span>
              <button className={styles.retryBtn} onClick={handleRegenerate}>
                <RefreshCw size={12} />
                Retry
              </button>
            </div>
          )}

          {generatedCypher && (
            <>
              <div className={styles.cypherBlock}>
                <label className={styles.label}>Generated Cypher</label>
                <pre className={styles.cypherCode}>{generatedCypher}</pre>
              </div>

              <div className={styles.previewSection}>
                <div className={styles.previewHeader}>
                  <span className={styles.label}>
                    Preview {nodeCount > 0 && `(${nodeCount} nodes)`}
                  </span>
                  <button className={styles.retryBtn} onClick={handleRegenerate}>
                    <RefreshCw size={12} />
                    Regenerate
                  </button>
                </div>
                <div ref={canvasRef} className={styles.previewCanvas}>
                  <GraphCanvas
                    data={previewData ?? undefined}
                    isLoading={previewLoading}
                    error={previewError ? new Error(previewError) : null}
                    projectId={projectId}
                    is3D={is3D}
                    width={dimensions.width}
                    height={dimensions.height}
                    showLabels={showLabels}
                    selectedNode={selectedNode}
                    onNodeClick={setSelectedNode}
                    isDark={isDark}
                  />
                </div>
              </div>

              <div className={styles.saveRow}>
                <input
                  className={styles.nameInput}
                  placeholder="View name"
                  value={viewName}
                  onChange={e => setViewName(e.target.value)}
                />
                <button
                  className={styles.saveBtn}
                  onClick={handleSave}
                  disabled={!viewName.trim() || saving}
                >
                  {saving ? (
                    <Loader2 size={14} className={styles.spin} />
                  ) : (
                    <Play size={14} />
                  )}
                  <span>{saving ? 'Saving...' : 'Save View'}</span>
                </button>
                <button className={styles.discardBtn} onClick={handleBack}>
                  Discard
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    )
  }

  // ── PREVIEW MODE ──
  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <button className={styles.backBtn} onClick={handleBack}>
          <ArrowLeft size={14} />
          <span>Back</span>
        </button>
        <div className={styles.headerLeft}>
          <h2 className={styles.title}>{activePreviewView?.name}</h2>
          {activePreviewView?.description && (
            <span className={styles.subtitle}>{activePreviewView.description}</span>
          )}
        </div>
        <span className={styles.nodeCountBadge}>
          {nodeCount} nodes
        </span>
        <button
          className={styles.iconBtn}
          onClick={(e) => activePreviewView && handleDeleteView(activePreviewView.id, e)}
          title="Delete view"
        >
          <Trash2 size={13} />
        </button>
      </div>

      <div ref={canvasRef} className={styles.previewCanvasFull}>
        <GraphCanvas
          data={previewData ?? undefined}
          isLoading={previewLoading}
          error={previewError ? new Error(previewError) : null}
          projectId={projectId}
          is3D={is3D}
          width={dimensions.width}
          height={dimensions.height}
          showLabels={showLabels}
          selectedNode={selectedNode}
          onNodeClick={setSelectedNode}
          isDark={isDark}
        />
      </div>
    </div>
  )
}
