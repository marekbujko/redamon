import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '../../graph/neo4j'
import { formatGraphRecords } from '../../graph/format'
import { injectProjectFilter } from './injectProjectFilter'

/**
 * Execute a Cypher query (from a saved graph view) against Neo4j,
 * injecting project_id tenant filter, and return formatted graph data.
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { cypherQuery, projectId } = body

    if (!cypherQuery || !projectId) {
      return NextResponse.json(
        { error: 'cypherQuery and projectId are required' },
        { status: 400 }
      )
    }

    // Inject project_id filter into every node pattern in the Cypher query.
    const filtered = injectProjectFilter(cypherQuery)

    const session = getSession()
    try {
      const result = await session.run(filtered, { projectId })
      const { nodes, links } = formatGraphRecords(result.records)
      return NextResponse.json({ nodes, links, projectId })
    } finally {
      await session.close()
    }
  } catch (error) {
    console.error('Graph view execute error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query execution failed' },
      { status: 500 }
    )
  }
}
