# ADD PARTIAL RECON FOR A NEW PIPELINE SECTION

Extend the partial recon system to support a new tool/section from the recon pipeline. Partial recon lets users run a single pipeline phase on demand from the workflow graph, without running the full pipeline. Results are merged into the existing Neo4j graph (always deduplicated via MERGE).

> **Reference implementations**: SubdomainDiscovery and Naabu are fully implemented. **Study Naabu as the primary pattern** -- it demonstrates user inputs, graph querying, structured targets, and the full data flow.

---

## Critical Rules

- **NEVER duplicate recon code.** Import and call the exact same functions from the existing pipeline modules (`domain_recon.py`, `port_scan.py`, `http_probe.py`, etc.). The partial recon entry point is a thin orchestration layer.
- **All graph writes use MERGE.** Neo4j uniqueness constraints prevent duplicates. Never use CREATE for nodes that might already exist.
- **Container-based execution.** Partial recon runs inside the same `redamon-recon` Docker image as the full pipeline, with a different command (`python /app/recon/partial_recon.py`). The orchestrator manages the container lifecycle.
- **Settings come from `get_settings()`.** The recon container fetches project settings via the webapp API (camelCase to UPPER_SNAKE_CASE conversion). Never pass raw camelCase settings.
- **Input node types come from `nodeMapping.ts`.** This is the single source of truth for what each tool consumes and produces. The modal reads from this mapping.
- **Each input type gets its own textarea + validation.** Never mix input types in a single textarea. Each has its own validator, error display, and graph association logic.
- **Validate on BOTH frontend and backend.** Frontend validates inline (regex, domain ownership, CIDR range) and disables Run on errors. Backend re-validates and skips invalid entries with log messages.
- **User input graph strategy -- choose by type:**
  - **Subdomain** -> always attaches to the project's Domain (only one domain per project). Create real Subdomain + IP + RESOLVES_TO nodes directly. No UserInput.
  - **Any other node type** (IP, URL, etc.) -> user must choose which existing node to attach to via a dropdown, OR select "Generic (UserInput)" for orphan provenance.
  - If attachment target doesn't exist at scan time, fall back to UserInput automatically.
- **Mutual exclusion.** Only one partial recon OR full recon can run at a time per project. The orchestrator enforces this (409 Conflict).
- **Rebuild the recon image** after changing `recon/partial_recon.py`: `docker compose --profile tools build recon`

---

## Architecture Overview

```
User clicks Play on tool node (ProjectForm) 
  -> PartialReconModal opens (shows input/output nodes, per-type input textareas)
  -> Frontend validates each textarea independently (IP format, CIDR range, subdomain domain ownership)
  -> For non-subdomain inputs: user selects attachment node from dropdown (or "Generic")
  -> User clicks "Run" (disabled if any validation errors)
  -> Frontend POST /api/recon/{projectId}/partial  { user_targets: {subdomains, ips, ip_attach_to} }
  -> Proxied to orchestrator POST /recon/{project_id}/partial  
  -> Orchestrator writes config JSON to /tmp/redamon/, spawns recon container
  -> Container runs: python /app/recon/partial_recon.py
  -> partial_recon.py reads config, processes user_targets, calls tool function
  -> Updates Neo4j graph via mixin methods
  -> Orchestrator streams logs via SSE
  -> Graph page shows drawer with real-time logs (no phase progress bar for partial recon)
```

### End-to-End Data Flow (verified for Naabu)

```
1. Modal builds: { tool_id, graph_inputs, user_inputs:[], user_targets: {subdomains, ips, ip_attach_to}, dedup_enabled }
2. ProjectForm.handlePartialReconConfirm: JSON.stringify(params) -> POST /api/recon/{projectId}/partial
   [passes full params as-is]
3. Proxy route (partial/route.ts): destructures body, adds project metadata, forwards to orchestrator
   [must include user_targets: body.user_targets || null]
4. Orchestrator model (models.py): PartialReconStartRequest validates via Pydantic
   [user_targets: dict | None = None]
5. Orchestrator API (api.py): builds config dict, includes "user_targets": request.user_targets
6. Container manager: json.dump(config) -> /tmp/redamon/partial_{project_id}.json
7. Container: load_config() reads JSON, run_naabu(config) reads config["user_targets"]
8. Processing: subdomains resolved FIRST, then IPs injected (order matters for cross-references)
```

---

## Modal Input Design Pattern

**Each input type the tool accepts gets its own section in the modal.** This is the core UI pattern:

### Rule: Subdomains always auto-attach to Domain
Since there is only one Domain per project, subdomains always belong to it. No dropdown needed -- just validate that the subdomain ends with `.{projectDomain}`.

### Rule: All other input types need a "Associate to" dropdown
IPs, URLs, or any other user values need explicit association. The dropdown offers:
- `"-- Generic (UserInput) --"` (default) -- creates a UserInput node
- Existing nodes from the graph (fetched via graph-inputs API)
- Custom nodes from other textareas in the same modal (live-updated)

### Naabu Example (implemented reference)

```
+------------------------------------------+
| Custom subdomains (optional)             |
| +--------------------------------------+ |
| | api.example.com                      | |
| | staging.example.com                  | |
| +--------------------------------------+ |
| Will be DNS-resolved and added to graph  |
|                                          |
| Custom IPs (optional)                    |
| +--------------------------------------+ |
| | 10.0.0.1                             | |
| | 10.0.0.2                             | |
| | 192.168.1.0/24                       | |
| +--------------------------------------+ |
| Associate to: [v -- Generic (UserInput)] |
|               -- Generic (UserInput) --  |
|               www.example.com    (graph) |
|               api.example.com      (new) |
+------------------------------------------+
```

**State:**
```typescript
const [customSubdomains, setCustomSubdomains] = useState('')
const [customIps, setCustomIps] = useState('')
const [ipAttachTo, setIpAttachTo] = useState<string | null>(null)
```

**Dropdown options built from (via `useMemo`):**
1. `graphInputs.existing_subdomains` (fetched from graph-inputs API)
2. Valid custom subdomains from Section A textarea (live-parsed)
3. `"-- Generic (UserInput) --"` option (value: `null`)

**The dropdown only appears when IPs textarea has content and no validation errors.**

**On "Run":**
```typescript
const userTargets: UserTargets = {
  subdomains: customSubdomains.split('\n').map(s => s.trim()).filter(Boolean),
  ips: customIps.split('\n').map(s => s.trim()).filter(Boolean),
  ip_attach_to: ipAttachTo,
}
```

---

## What to Implement for Each New Tool

### 1. Backend: `recon/partial_recon.py`

Add a `run_<tool_name>(config)` function. It reads `config["user_targets"]` for structured input:

```python
user_targets = config.get("user_targets") or {}
user_subdomains = user_targets.get("subdomains", [])
user_ips = user_targets.get("ips", [])
ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

# Fall back to legacy flat user_inputs for backward compat
if not user_targets and config.get("user_inputs"):
    # classify each entry with _is_ip_or_cidr() / _is_valid_hostname()
```

**Processing order matters:**
1. **Subdomains FIRST** -- resolve via `_resolve_hostname()`, create Subdomain + IP + RESOLVES_TO in graph, inject into `recon_data`
2. **IPs SECOND** -- this ensures subdomain exists if `ip_attach_to` references a custom subdomain from step 1

**IP attachment logic:**
- `ip_attach_to` is a subdomain name: inject IPs into `recon_data["dns"]["subdomains"][ip_attach_to]["ips"]`, then post-scan create `Subdomain -[:RESOLVES_TO]-> IP`
- `ip_attach_to` is `null`: inject IPs into `recon_data["dns"]["domain"]["ips"]`, create UserInput node, post-scan link `UserInput -[:PRODUCED]-> IP`
- **Safety fallback**: if `ip_attach_to` subdomain doesn't exist in graph after resolution, automatically fall back to UserInput (prevents orphan IPs)

**Register in `main()`:**
```python
elif tool_id == "<NewToolId>":
    run_<tool_name>(config)
```

### 2. Backend: Graph Mixin

File: `graph_db/mixins/recon_mixin.py`

Reuse existing `update_graph_from_<stage>()` methods. Add a case to `get_graph_inputs_for_tool()` that returns counts AND node name lists (for the dropdown).

**Naabu example** -- returns subdomain names for the "Associate to" dropdown:
```python
elif tool_id == "Naabu":
    result = session.run("""
        OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
        OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
        WITH d, collect(DISTINCT s.name) AS subdomains,
             count(DISTINCT i) + count(DISTINCT di) AS ipCount
        RETURN d.name AS domain, subdomains, size(subdomains) AS subCount, ipCount
    """, uid=user_id, pid=project_id)
```

### 3. Frontend: Types (`recon-types.ts`)

```typescript
// Add to PARTIAL_RECON_SUPPORTED_TOOLS
export const PARTIAL_RECON_SUPPORTED_TOOLS = new Set(['SubdomainDiscovery', 'Naabu', '<NewToolId>'])

// Add to PARTIAL_RECON_PHASE_MAP (NOT the flat PARTIAL_RECON_PHASES)
export const PARTIAL_RECON_PHASE_MAP: Record<string, readonly string[]> = {
  SubdomainDiscovery: ['Subdomain Discovery'],
  Naabu: ['Port Scanning'],
  '<NewToolId>': ['<Phase Name>'],
}

// Extend GraphInputs if needed (add existing_<type> list for dropdown)
export interface GraphInputs {
  domain: string | null
  existing_subdomains_count: number
  existing_subdomains?: string[]     // for Naabu dropdown
  existing_ips_count?: number
  existing_baseurls?: string[]       // for future tools
  source: 'graph' | 'settings'
}

// UserTargets carries structured inputs (per-type)
export interface UserTargets {
  subdomains: string[]
  ips: string[]
  ip_attach_to: string | null
  // Future tools may add: urls: string[], url_attach_to: string | null, etc.
}
```

### 4. Frontend: Graph Inputs API Route

File: `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts`

Add `else if (toolId === '<NewToolId>')` -- return node name lists for dropdown alongside counts. Must use `else if`, not `if`.

### 5. Frontend: PartialReconModal

File: `webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx`

For each new tool:
1. Add tool description to `TOOL_DESCRIPTIONS`
2. Add per-type input sections (conditional on `toolId`):
   - **Subdomain textarea**: validates hostname regex + domain ownership. No dropdown needed.
   - **IP textarea** (or URL, etc.): validates format. Show "Associate to" dropdown below with graph nodes + custom subdomains + "Generic".
3. Each textarea has its own `useMemo` validator. `hasValidationErrors` is OR of all.
4. `handleRun` builds `UserTargets` from all textarea states.
5. Show warning if graph has no data for this tool.

**Validation helpers already exist:**
- `validateIp(value)` -- IPv4 octets, IPv6, CIDR /24-/32
- `validateSubdomain(value, projectDomain)` -- hostname regex + domain ownership
- `validateLines(text, validator)` -- runs validator per line, returns `{errors, validCount}`

### 6. Frontend: Proxy Route

File: `webapp/src/app/api/recon/[projectId]/partial/route.ts`

Already passes `user_targets: body.user_targets || null`. No changes needed for new tools.

### 7. Backend: Orchestrator

Files: `recon_orchestrator/models.py` + `recon_orchestrator/api.py`

Already has `user_targets: dict | None = None` in model and passes it to config. No changes needed.

### 8. Frontend: Drawer & Toolbar (already generic)

No changes needed:
- Drawer title uses `WORKFLOW_TOOLS.find()` lookup
- Toolbar badge uses `WORKFLOW_TOOLS.find()` lookup  
- Phase progress hidden for partial recon via `hidePhaseProgress`
- Status shows `"Scanning: <phase>"` instead of `"Phase 1/1: <phase>"`

---

## File Reference

### Files you MUST modify:

| File | What to change |
|------|----------------|
| `recon/partial_recon.py` | Add `run_<tool>(config)` + register in `main()` |
| `webapp/src/lib/recon-types.ts` | Add to `PARTIAL_RECON_SUPPORTED_TOOLS` + `PARTIAL_RECON_PHASE_MAP`, extend `UserTargets` if needed |
| `webapp/src/components/.../PartialReconModal.tsx` | Add per-type textareas + validation + dropdown for the tool |

### Files you MAY need to modify:

| File | When |
|------|------|
| `graph_db/mixins/recon_mixin.py` | Add `get_graph_inputs_for_tool()` case with node name lists |
| `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts` | Add tool-specific Neo4j query for counts + names |
| `webapp/src/lib/recon-types.ts` | Extend `GraphInputs` / `UserTargets` if tool has new input types |
| `recon/tests/test_partial_recon.py` | Add test class for new tool |
| `webapp/src/lib/partial-recon-types.test.ts` | Update supported tools, phase map, type shape tests |

### Files you should NOT modify:

| File | Why |
|------|-----|
| `recon/domain_recon.py`, `port_scan.py`, `http_probe.py`, etc. | Source pipeline modules. Import, don't modify. |
| `recon/main.py` | Full pipeline. Partial recon is independent. |
| `recon_orchestrator/api.py` | Already passes `user_targets` generically. |
| `recon_orchestrator/models.py` | Already has `user_targets: dict \| None`. |
| `recon_orchestrator/container_manager.py` | Generic. Writes whatever config it receives. |
| `webapp/src/app/api/recon/[projectId]/partial/route.ts` | Already passes `user_targets`. |
| `webapp/src/hooks/usePartialRecon*.ts` | Generic hooks. |
| `webapp/src/components/.../ToolNode.tsx` | Checks `PARTIAL_RECON_SUPPORTED_TOOLS`. |
| `webapp/src/components/.../WorkflowView.tsx`, `ProjectForm.tsx` | Already generic. |
| `webapp/src/app/graph/page.tsx` | Uses `PARTIAL_RECON_PHASE_MAP`. |
| `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx` | Uses `WORKFLOW_TOOLS.find()`. |
| `webapp/src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.tsx` | Has `hidePhaseProgress`. |

### Key reference files (read-only):

| File | Contains |
|------|----------|
| `webapp/src/components/projects/ProjectForm/nodeMapping.ts` | `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` -- tool I/O node types |
| `webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts` | `WORKFLOW_TOOLS` -- tool IDs, labels, groups |
| `graph_db/schema.py` | Neo4j constraints and indexes |
| `recon/project_settings.py` | `get_settings()` + `DEFAULT_SETTINGS` |
| `recon/main.py` | Full pipeline -- see what `recon_data` structure each tool expects |

---

## Naabu Reference Implementation (study this)

Naabu is the reference for any tool that needs user inputs. Read these files in order:

### 1. Frontend: Modal inputs
**`PartialReconModal.tsx`** -- search for `isNaabu`:
- Section A: `customSubdomains` textarea with `validateSubdomain()` per line
- Section B: `customIps` textarea with `validateIp()` per line
- Dropdown: `ipAttachTo` select, options from `attachToOptions` (graph + custom, via `useMemo`)
- `handleRun` builds `UserTargets` only when there's actual custom input

### 2. Frontend: Graph inputs API  
**`graph-inputs/[toolId]/route.ts`** -- Naabu case:
- Cypher query returns `collect(DISTINCT s.name) AS subdomains` (name list for dropdown)
- Returns `{ domain, existing_subdomains, existing_subdomains_count, existing_ips_count, source }`

### 3. Backend: Processing
**`partial_recon.py` -- `run_naabu()`:**
- Reads `config["user_targets"]` with legacy `user_inputs` fallback
- STEP 1: Resolves hostnames, creates Subdomain + IP + RESOLVES_TO in Neo4j
- STEP 2: Injects IPs into `recon_data` (into subdomain bucket if `ip_attach_to`, or domain bucket if generic)
- Safety: if `ip_attach_to` subdomain doesn't exist in graph, falls back to UserInput
- Calls `run_port_scan(recon_data, settings=settings)` -- same function as full pipeline
- Post-scan: creates `Subdomain -[:RESOLVES_TO]-> IP` or `UserInput -[:PRODUCED]-> IP` depending on `ip_attach_to`

### 4. Graph relationships created
```
User provides subdomain:
  Domain -[:HAS_SUBDOMAIN]-> Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port

User provides IP attached to subdomain:
  Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port

User provides IP (generic):
  Domain -[:HAS_USER_INPUT]-> UserInput -[:PRODUCED]-> IP -[:HAS_PORT]-> Port
```

---

## Tool-Specific Notes

### Port Scanning (Naabu) -- IMPLEMENTED
- **Input from graph**: IPs and Subdomains (via `_build_recon_data_from_graph()`)
- **Tool function**: `run_port_scan(recon_data, settings=settings)` from `port_scan.py`
- **Graph update**: `update_graph_from_port_scan()` -- Port, Service nodes
- **User inputs**: Subdomains (auto-attach to Domain) + IPs (dropdown: attach to subdomain or generic)
- **Note**: `run_port_scan` mutates `recon_data` adding `port_scan` key. Docker-in-Docker. SYN scan with CONNECT fallback.

### HTTP Probing (Httpx)
- **Input from graph**: Subdomains + Ports
- **Tool function**: `run_http_probe(recon_data, settings=settings)` from `http_probe.py`
- **Graph update**: `update_graph_from_http_probe()` -- BaseURL, Technology, Header, Certificate
- **User inputs**: Subdomains (auto-attach) + URLs (dropdown: attach to subdomain or generic)

### Resource Enumeration (Katana, etc.)
- **Input from graph**: BaseURLs
- **Tool function**: `run_resource_enum(recon_data, settings=settings)` from `resource_enum.py`
- **Graph update**: `update_graph_from_resource_enum()` -- Endpoint, Parameter
- **User inputs**: URLs (dropdown: attach to BaseURL or generic)

### Vulnerability Scanning (Nuclei)
- **Input from graph**: BaseURLs + Endpoints
- **Tool function**: `run_vuln_scan(recon_data, settings=settings)` from `vuln_scan.py`
- **Graph update**: `update_graph_from_vuln_scan()` -- Vulnerability, CVE, MitreData, Capec
- **User inputs**: URLs (dropdown: attach to BaseURL or generic)

### JS Recon
- **Input from graph**: BaseURLs + Endpoints (JS files)
- **Tool function**: `run_js_recon(combined_result, settings)` from `js_recon.py`
- **Graph update**: `update_graph_from_js_recon()` -- JsReconFinding, Secret, Endpoint

---

## UserInput Node Strategy

**Rule: Subdomains auto-attach to Domain. Everything else: user chooses via dropdown.**

| User provides | Attachment | Strategy |
|---|---|---|
| Subdomain | Auto -> Domain (only one per project) | Create Subdomain + IP + RESOLVES_TO. No UserInput. |
| IP attached to subdomain | User selects subdomain | Create `Subdomain -[:RESOLVES_TO]-> IP`. No UserInput. |
| IP generic | User selects "Generic" | `UserInput -[:PRODUCED]-> IP` |
| URL attached to BaseURL | User selects BaseURL | Create Endpoint under BaseURL. No UserInput. |
| URL generic | User selects "Generic" | `UserInput -[:PRODUCED]-> Endpoint` |

**Safety fallback**: if the selected attachment node doesn't exist at scan time (deleted between modal open and run), the backend detects this via a graph query and automatically falls back to UserInput. No orphan nodes.

---

## Helper Functions in `partial_recon.py`

Reuse these -- do not reimplement:

| Function | Purpose |
|----------|---------|
| `_classify_ip(address, version=None)` | Returns `"ipv4"` or `"ipv6"`. |
| `_is_ip_or_cidr(value)` | Validates IP or CIDR. |
| `_is_valid_hostname(value)` | Validates hostname regex. |
| `_resolve_hostname(hostname)` | DNS resolves via `socket.getaddrinfo()`. Returns `{"ipv4": [...], "ipv6": [...]}`. |
| `_build_recon_data_from_graph(domain, user_id, project_id)` | Queries Neo4j, returns `recon_data` dict for `extract_targets_from_recon()`. |
| `load_config()` | Loads JSON config from `PARTIAL_RECON_CONFIG` env var. |

---

## Frontend Validation

Separate validators per input type (in `PartialReconModal.tsx`):

| Validator | Input type | Rules |
|---|---|---|
| `validateSubdomain(value, domain)` | Hostnames | Hostname regex + must end with `.{domain}` or equal `{domain}` |
| `validateIp(value)` | IPs/CIDRs | IPv4 octets 0-255, IPv6 format, CIDR /24-/32 (v4) or /120-/128 (v6) |

Each textarea runs its validator per line via `validateLines(text, validator)` in `useMemo`. Errors show per-line below each textarea. Run button disabled if any textarea has errors.

---

## Build & Verification

After implementing:

1. `docker compose --profile tools build recon` (code baked into image)
2. `docker compose restart recon-orchestrator` (if you changed models.py or api.py)
3. Dev webapp hot-reloads (no rebuild for frontend)
4. Click play on the new tool in workflow graph
5. Verify: modal shows separate textareas per input type
6. Verify: dropdown shows existing graph nodes + custom subdomains from textarea
7. Verify: validation works per textarea (invalid entries, wrong domain, oversized CIDR)
8. Verify: Run button disabled while errors exist
9. Click Run, check logs drawer (no phase dots, shows "Scanning: <name>")
10. Query Neo4j: subdomains created as real nodes, IPs linked via RESOLVES_TO or UserInput
11. **Compare with Naabu**: run Naabu partial recon to see the reference behavior

---

## Existing Tests

**Python** (`recon/tests/test_partial_recon.py`):
- `TestLoadConfig` -- config loading
- `TestClassifyIp` -- IP classification
- `TestIsIpOrCidr` / `TestIsValidHostname` -- validation helpers
- `TestBuildReconDataFromGraph` -- graph data reconstruction
- `TestRunSubdomainDiscovery` -- subdomain discovery orchestration
- `TestRunNaabu` -- port scan with legacy flat inputs
- `TestRunNaabuCidrExpansion` -- CIDR expansion, dedup, IPv6
- `TestRunNaabuHostnameInputs` -- hostname resolution, graph node creation
- `TestRunNaabuStructuredTargets` -- new `user_targets` format: attach to subdomain, generic, backward compat

**TypeScript** (`webapp/src/lib/partial-recon-types.test.ts`):
- Type shape validation for `UserTargets`, `GraphInputs`, `PartialReconParams`
- Supported tools and phase map

Add tests for the new tool following the same patterns.
