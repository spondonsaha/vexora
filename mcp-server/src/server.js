import express from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { z } from 'zod'

const PORT = Number(process.env.MCP_PORT ?? 3001)
const API_BASE_URL = process.env.API_BASE_URL ?? 'http://localhost:8080'
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? ''
const TOOL_COUNT = 6

async function apiFetch(path, init) {
  const res = await fetch(`${API_BASE_URL}/api/v1${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  const text = await res.text()
  let body
  try {
    body = text ? JSON.parse(text) : undefined
  } catch {
    body = text
  }
  if (!res.ok) {
    const message = body?.error?.message ?? res.statusText
    throw new Error(`API ${res.status}: ${message}`)
  }
  return body
}

function text(value) {
  return {
    content: [
      {
        type: 'text',
        text: typeof value === 'string' ? value : JSON.stringify(value, null, 2),
      },
    ],
  }
}

function createServer() {
  const server = new McpServer({ name: 'vexora', version: '0.1.0' })

  server.tool('health', 'Backend API and database health.', {}, async () =>
    text(await apiFetch('/health')),
  )

  server.tool(
    'list_scope_targets',
    'List all scope targets, optionally filtered by type.',
    { type: z.enum(['company', 'wildcard', 'url']).optional() },
    async ({ type }) => text(await apiFetch(`/scope-targets${type ? `?type=${type}` : ''}`)),
  )

  server.tool(
    'get_scope_target',
    'Get a single scope target by id.',
    { id: z.string().uuid() },
    async ({ id }) => text(await apiFetch(`/scope-targets/${id}`)),
  )

  server.tool(
    'create_scope_target',
    'Create a scope target. auth_confirmed must be true to acknowledge authorization.',
    {
      type: z.enum(['company', 'wildcard', 'url']),
      value: z.string().min(1),
      description: z.string().optional(),
      auth_confirmed: z.boolean(),
    },
    async ({ type, value, description, auth_confirmed }) =>
      text(
        await apiFetch('/scope-targets', {
          method: 'POST',
          body: JSON.stringify({ type, value, description, auth_confirmed }),
        }),
      ),
  )

  server.tool(
    'activate_scope_target',
    'Activate a scope target for scanning. Refused unless authorization is confirmed.',
    { id: z.string().uuid(), auth_confirmed: z.boolean().optional() },
    async ({ id, auth_confirmed }) =>
      text(
        await apiFetch(`/scope-targets/${id}/activate`, {
          method: 'PATCH',
          body: JSON.stringify(
            auth_confirmed === undefined ? {} : { auth_confirmed },
          ),
        }),
      ),
  )

  server.tool(
    'delete_scope_target',
    'Delete a scope target and its dependent data.',
    { id: z.string().uuid() },
    async ({ id }) => {
      await apiFetch(`/scope-targets/${id}`, { method: 'DELETE' })
      return text(`scope target ${id} deleted`)
    },
  )

  return server
}

const app = express()
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'vexora-mcp', tools: TOOL_COUNT })
})

function requireAuth(req, res, next) {
  if (!AUTH_TOKEN) return next()
  const header = req.header('authorization') ?? ''
  if (header === `Bearer ${AUTH_TOKEN}`) return next()
  res.status(401).json({ error: 'unauthorized' })
}
app.use(requireAuth)

const transports = new Map()

app.get('/sse', async (req, res) => {
  const transport = new SSEServerTransport('/messages', res)
  transports.set(transport.sessionId, transport)
  res.on('close', () => transports.delete(transport.sessionId))

  const server = createServer()
  await server.connect(transport)
})

app.post('/messages', async (req, res) => {
  const sessionId = String(req.query.sessionId ?? '')
  const transport = transports.get(sessionId)
  if (!transport) {
    res.status(400).json({ error: 'no transport for session' })
    return
  }
  await transport.handlePostMessage(req, res)
})

app.listen(PORT, () => {
  console.log(`vexora-mcp listening on :${PORT} (tools=${TOOL_COUNT}, auth=${AUTH_TOKEN ? 'on' : 'off'})`)
})
