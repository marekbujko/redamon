import { describe, test, expect } from 'vitest'
import {
  PARTIAL_RECON_SUPPORTED_TOOLS,
  PARTIAL_RECON_PHASES,
  PARTIAL_RECON_PHASE_MAP,
} from './recon-types'
import type {
  PartialReconStatus,
  PartialReconState,
  GraphInputs,
  PartialReconParams,
  UserTargets,
} from './recon-types'

// === PARTIAL_RECON_SUPPORTED_TOOLS ===
describe('PARTIAL_RECON_SUPPORTED_TOOLS', () => {
  test('contains SubdomainDiscovery', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SubdomainDiscovery')).toBe(true)
  })

  test('contains Naabu', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Naabu')).toBe(true)
  })

  test('does not contain unsupported tools', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nuclei')).toBe(false)
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Httpx')).toBe(false)
  })
})

// === PARTIAL_RECON_PHASE_MAP ===
describe('PARTIAL_RECON_PHASE_MAP', () => {
  test('has SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery'][0]).toBe('Subdomain Discovery')
  })

  test('has Naabu phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Naabu']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Naabu'][0]).toBe('Port Scanning')
  })

  test('each supported tool has a phase entry', () => {
    for (const toolId of PARTIAL_RECON_SUPPORTED_TOOLS) {
      expect(PARTIAL_RECON_PHASE_MAP[toolId]).toBeDefined()
      expect(PARTIAL_RECON_PHASE_MAP[toolId].length).toBeGreaterThan(0)
    }
  })
})

// === PARTIAL_RECON_PHASES (backward compat) ===
describe('PARTIAL_RECON_PHASES', () => {
  test('defaults to SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASES).toHaveLength(1)
    expect(PARTIAL_RECON_PHASES[0]).toBe('Subdomain Discovery')
  })

  test('is an array', () => {
    expect(Array.isArray(PARTIAL_RECON_PHASES)).toBe(true)
  })
})

// === Type Shape Validation ===
describe('PartialReconState type shape', () => {
  test('default idle state has required fields', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'idle',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.project_id).toBe('proj-123')
    expect(state.status).toBe('idle')
    expect(state.stats).toBeNull()
  })

  test('completed state with stats', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'completed',
      container_id: 'abc123',
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:05:00Z',
      error: null,
      stats: { subdomains_total: 15, subdomains_new: 8, subdomains_existing: 7, ips_total: 12 },
    }
    expect(state.stats?.subdomains_new).toBe(8)
    expect(state.stats?.subdomains_existing).toBe(7)
  })

  test('error state with error message', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'error',
      container_id: null,
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:01:00Z',
      error: 'Container exited with code 1',
      stats: null,
    }
    expect(state.error).toBeTruthy()
  })
})

describe('PartialReconStatus values', () => {
  test.each<PartialReconStatus>([
    'idle', 'starting', 'running', 'completed', 'error', 'stopping',
  ])('accepts valid status: %s', (status) => {
    const state: PartialReconState = {
      project_id: 'p', tool_id: 't', status,
      container_id: null, started_at: null, completed_at: null, error: null, stats: null,
    }
    expect(state.status).toBe(status)
  })
})

describe('GraphInputs type shape', () => {
  test('from graph source', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 42,
      source: 'graph',
    }
    expect(inputs.source).toBe('graph')
    expect(inputs.existing_subdomains_count).toBe(42)
  })

  test('from settings fallback', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.source).toBe('settings')
    expect(inputs.existing_subdomains_count).toBe(0)
  })

  test('null domain when no data', () => {
    const inputs: GraphInputs = {
      domain: null,
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.domain).toBeNull()
  })

  test('with existing_ips_count for Naabu', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_ips_count).toBe(5)
  })
})

describe('PartialReconParams type shape', () => {
  test('minimal params', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      dedup_enabled: true,
    }
    expect(params.tool_id).toBe('SubdomainDiscovery')
    expect(params.user_inputs).toHaveLength(0)
    expect(params.dedup_enabled).toBe(true)
    expect(params.settings_overrides).toBeUndefined()
  })

  test('full params with user inputs and overrides', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: ['api.example.com', 'admin.example.com'],
      dedup_enabled: false,
      settings_overrides: { SUBFINDER_ENABLED: false },
    }
    expect(params.user_inputs).toHaveLength(2)
    expect(params.dedup_enabled).toBe(false)
    expect(params.settings_overrides).toBeDefined()
  })

  test('Naabu params with structured user_targets', () => {
    const targets: UserTargets = {
      subdomains: ['api.example.com'],
      ips: ['10.0.0.1', '192.168.1.0/24'],
      ip_attach_to: 'api.example.com',
    }
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: targets,
      dedup_enabled: true,
    }
    expect(params.tool_id).toBe('Naabu')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(2)
    expect(params.user_targets?.ip_attach_to).toBe('api.example.com')
  })

  test('Naabu params with generic IPs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: [], ips: ['10.0.0.1'], ip_attach_to: null },
      dedup_enabled: true,
    }
    expect(params.user_targets?.ip_attach_to).toBeNull()
  })

  test('Naabu params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      dedup_enabled: true,
    }
    expect(params.user_targets).toBeUndefined()
  })
})

describe('GraphInputs with existing_subdomains', () => {
  test('Naabu graph inputs include subdomain list', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 2,
      existing_subdomains: ['www.example.com', 'api.example.com'],
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_subdomains).toHaveLength(2)
    expect(inputs.existing_subdomains).toContain('api.example.com')
  })
})
