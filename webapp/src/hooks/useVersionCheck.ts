'use client'

import { useState, useEffect, useCallback } from 'react'
import { isNewerVersion } from '@/lib/semver'
import type { ChangelogEntry } from '@/lib/parseChangelog'

const SESSION_CACHE_KEY = 'redamon-version-check'
const DISMISSED_KEY = 'redamon-dismissed-version'

interface VersionCheckResult {
  current_version: string
  latest_version: string | null
  changelog: ChangelogEntry[]
}

interface VersionCheckState {
  currentVersion: string
  latestVersion: string | null
  changelog: ChangelogEntry[]
  updateAvailable: boolean
  isDismissed: boolean
  loading: boolean
  checkForUpdates: () => void
  dismissUpdate: () => void
}

export function useVersionCheck(): VersionCheckState {
  const [currentVersion, setCurrentVersion] = useState('0.0.0')
  const [latestVersion, setLatestVersion] = useState<string | null>(null)
  const [changelog, setChangelog] = useState<ChangelogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [dismissedVersion, setDismissedVersion] = useState<string | null>(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem(DISMISSED_KEY)
    }
    return null
  })

  const updateAvailable = latestVersion !== null && isNewerVersion(currentVersion, latestVersion)
  const isDismissed = latestVersion !== null && dismissedVersion === latestVersion

  const fetchVersion = useCallback(async (useCache: boolean) => {
    // Check sessionStorage cache
    if (useCache && typeof window !== 'undefined') {
      const cached = sessionStorage.getItem(SESSION_CACHE_KEY)
      if (cached) {
        try {
          const data: VersionCheckResult = JSON.parse(cached)
          setCurrentVersion(data.current_version)
          setLatestVersion(data.latest_version)
          setChangelog(data.changelog)
          return
        } catch { /* ignore bad cache */ }
      }
    }

    setLoading(true)
    try {
      const res = await fetch('/api/version/check')
      if (!res.ok) return

      const data: VersionCheckResult = await res.json()
      if (data.current_version) {
        setCurrentVersion(data.current_version)
        setLatestVersion(data.latest_version)
        setChangelog(data.changelog || [])

        if (typeof window !== 'undefined') {
          sessionStorage.setItem(SESSION_CACHE_KEY, JSON.stringify(data))
        }
      }
    } catch {
      // Silent failure -- no error UI if GitHub is unreachable
    } finally {
      setLoading(false)
    }
  }, [])

  const checkForUpdates = useCallback(() => {
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(SESSION_CACHE_KEY)
    }
    fetchVersion(false)
  }, [fetchVersion])

  const dismissUpdate = useCallback(() => {
    if (latestVersion && typeof window !== 'undefined') {
      localStorage.setItem(DISMISSED_KEY, latestVersion)
      setDismissedVersion(latestVersion)
    }
  }, [latestVersion])

  // Initial fetch on mount
  useEffect(() => {
    fetchVersion(true)
  }, [fetchVersion])

  return {
    currentVersion,
    latestVersion,
    changelog,
    updateAvailable,
    isDismissed,
    loading,
    checkForUpdates,
    dismissUpdate,
  }
}
