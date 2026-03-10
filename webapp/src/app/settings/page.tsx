'use client'

import { useState, useEffect, useCallback } from 'react'
import { Plus, Pencil, Trash2, Loader2, Eye, EyeOff } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import type { ProviderData } from '@/components/settings/LlmProviderForm'
import { PROVIDER_TYPES } from '@/lib/llmProviderPresets'
import styles from '@/components/settings/Settings.module.css'

interface UserSettings {
  tavilyApiKey: string
}

const EMPTY_SETTINGS: UserSettings = {
  tavilyApiKey: '',
}

function getProviderIcon(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.icon || '⚙️'
}

function getProviderLabel(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.name || providerType
}

export default function SettingsPage() {
  const { userId } = useProject()

  // LLM Providers
  const [providers, setProviders] = useState<ProviderData[]>([])
  const [providersLoading, setProvidersLoading] = useState(true)
  const [showProviderForm, setShowProviderForm] = useState(false)
  const [editingProvider, setEditingProvider] = useState<ProviderData | null>(null)

  // User Settings
  const [settings, setSettings] = useState<UserSettings>(EMPTY_SETTINGS)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [visibleFields, setVisibleFields] = useState<Record<string, boolean>>({})

  // Fetch providers
  const fetchProviders = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/llm-providers`)
      if (resp.ok) setProviders(await resp.json())
    } catch (err) {
      console.error('Failed to fetch providers:', err)
    } finally {
      setProvidersLoading(false)
    }
  }, [userId])

  // Fetch user settings
  const fetchSettings = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/settings`)
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          tavilyApiKey: data.tavilyApiKey || '',
        })
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err)
    } finally {
      setSettingsLoading(false)
    }
  }, [userId])

  useEffect(() => {
    fetchProviders()
    fetchSettings()
  }, [fetchProviders, fetchSettings])

  // Delete provider
  const deleteProvider = useCallback(async (providerId: string) => {
    if (!userId || !confirm('Delete this provider? Models from it will no longer be available.')) return
    try {
      await fetch(`/api/users/${userId}/llm-providers/${providerId}`, { method: 'DELETE' })
      fetchProviders()
    } catch (err) {
      console.error('Failed to delete provider:', err)
    }
  }, [userId, fetchProviders])

  // Save user settings
  const saveSettings = useCallback(async () => {
    if (!userId) return
    setSettingsSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      })
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          tavilyApiKey: data.tavilyApiKey || '',
        })
        setSettingsDirty(false)
      }
    } catch (err) {
      console.error('Failed to save settings:', err)
    } finally {
      setSettingsSaving(false)
    }
  }, [userId, settings])

  const updateSetting = useCallback(<K extends keyof UserSettings>(field: K, value: string) => {
    setSettings(prev => ({ ...prev, [field]: value }))
    setSettingsDirty(true)
  }, [])

  const toggleFieldVisibility = useCallback((field: string) => {
    setVisibleFields(prev => ({ ...prev, [field]: !prev[field] }))
  }, [])

  if (!userId) {
    return (
      <div className={styles.page}>
        <h1 className={styles.pageTitle}>Global Settings</h1>
        <div className={styles.emptyState}>Select a user to configure settings.</div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.pageTitle}>Global Settings</h1>

      {/* Section 1: LLM Providers */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>LLM Providers</h2>
          {!showProviderForm && !editingProvider && (
            <button className="primaryButton" onClick={() => setShowProviderForm(true)}>
              <Plus size={14} /> Add Provider
            </button>
          )}
        </div>
        <p className={styles.sectionHint}>
          Models from all providers appear in every project&apos;s LLM selector. Key-based providers auto-discover available models.
        </p>

        {/* Provider form */}
        {(showProviderForm || editingProvider) && (
          <LlmProviderForm
            userId={userId}
            provider={editingProvider}
            onSave={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
              fetchProviders()
            }}
            onCancel={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
            }}
          />
        )}

        {/* Provider list */}
        {!showProviderForm && !editingProvider && (
          providersLoading ? (
            <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
          ) : providers.length === 0 ? (
            <div className={styles.emptyState}>No providers configured. Add one to get started.</div>
          ) : (
            <div className={styles.providerList}>
              {providers.map((p: ProviderData) => (
                <div key={p.id} className={styles.providerCard}>
                  <span className={styles.providerIcon}>{getProviderIcon(p.providerType)}</span>
                  <div className={styles.providerInfo}>
                    <div className={styles.providerName}>{p.name}</div>
                    <div className={styles.providerMeta}>
                      {getProviderLabel(p.providerType)}
                      {p.providerType === 'openai_compatible' && p.modelIdentifier && ` — ${p.modelIdentifier}`}
                    </div>
                  </div>
                  <div className={styles.providerActions}>
                    <button className="iconButton" title="Edit" onClick={() => setEditingProvider(p)}>
                      <Pencil size={14} />
                    </button>
                    <button className="iconButton" title="Delete" onClick={() => deleteProvider(p.id!)}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      {/* Section 2: Tool API Keys */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>Tool API Keys</h2>
        </div>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="Tavily API Key"
              hint="Enables web_search tool for CVE research and exploit lookups"
              value={settings.tavilyApiKey}
              visible={!!visibleFields.tavilyApiKey}
              onToggle={() => toggleFieldVisibility('tavilyApiKey')}
              onChange={v => updateSetting('tavilyApiKey', v)}
            />
          </div>
        )}
      </div>

      {/* Save settings button */}
      {settingsDirty && (
        <div className={styles.formActions} style={{ justifyContent: 'flex-end' }}>
          <button className="primaryButton" onClick={saveSettings} disabled={settingsSaving}>
            {settingsSaving ? <Loader2 size={14} className={styles.spin} /> : null}
            Save Settings
          </button>
        </div>
      )}
    </div>
  )
}

// Reusable secret field component
function SecretField({
  label,
  hint,
  value,
  visible,
  onToggle,
  onChange,
}: {
  label: string
  hint: string
  value: string
  visible: boolean
  onToggle: () => void
  onChange: (v: string) => void
}) {
  return (
    <div className="formGroup">
      <label className="formLabel">{label}</label>
      <div className={styles.secretInputWrapper}>
        <input
          className="textInput"
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={`Enter ${label.toLowerCase()}`}
        />
        <button className={styles.secretToggle} onClick={onToggle} type="button">
          {visible ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
      <span className="formHint">{hint}</span>
    </div>
  )
}
