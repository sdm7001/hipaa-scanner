import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

interface AuditEntry {
  id: string
  user_id: string | null
  user_email: string | null
  action: string
  resource_type: string
  resource_id: string | null
  http_method: string
  path: string
  status_code: number | null
  ip_address: string | null
  created_at: string
}

interface AuditLogResponse {
  items: AuditEntry[]
  total: number
  page: number
  page_size: number
}

const METHOD_COLORS: Record<string, string> = {
  POST: 'text-emerald-400',
  PATCH: 'text-amber-400',
  PUT: 'text-amber-400',
  DELETE: 'text-red-400',
}

const STATUS_COLOR = (code: number | null) => {
  if (!code) return 'text-gray-500'
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-amber-400'
  return 'text-red-400'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

export default function AuditLog() {
  const [page, setPage] = useState(1)
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')

  const { data, isLoading } = useQuery<AuditLogResponse>({
    queryKey: ['audit-log', page, actionFilter, resourceFilter],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: String(page),
        page_size: '50',
      })
      if (actionFilter) params.set('action', actionFilter)
      if (resourceFilter) params.set('resource_type', resourceFilter)
      return (await api.get(`/audit-log/?${params}`)).data
    },
  })

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 1

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-white">Audit Log</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Immutable record of all portal actions — HIPAA 164.312(b) Audit Controls
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Filter by action (e.g. CREATE_USER)"
          value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1) }}
          className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
        <input
          type="text"
          placeholder="Filter by resource (e.g. user, client)"
          value={resourceFilter}
          onChange={e => { setResourceFilter(e.target.value); setPage(1) }}
          className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>

      {/* Stats bar */}
      {data && (
        <div className="text-xs text-gray-500">
          {data.total.toLocaleString()} total events &nbsp;·&nbsp; Page {data.page} of {totalPages}
        </div>
      )}

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-600">Loading audit records…</div>
        ) : !data?.items.length ? (
          <div className="p-8 text-center text-sm text-gray-600">No audit records found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-wide">
                  <th className="text-left px-4 py-3 font-medium">Time</th>
                  <th className="text-left px-4 py-3 font-medium">User</th>
                  <th className="text-left px-4 py-3 font-medium">Action</th>
                  <th className="text-left px-4 py-3 font-medium">Method</th>
                  <th className="text-left px-4 py-3 font-medium">Path</th>
                  <th className="text-left px-4 py-3 font-medium">Status</th>
                  <th className="text-left px-4 py-3 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((entry, i) => (
                  <tr
                    key={entry.id}
                    className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${
                      i % 2 === 0 ? '' : 'bg-gray-800/10'
                    }`}
                  >
                    <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap">
                      {formatDate(entry.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-gray-300 whitespace-nowrap">
                      {entry.user_email ?? <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-blue-400">{entry.action}</span>
                    </td>
                    <td className={`px-4 py-2.5 font-mono font-bold ${METHOD_COLORS[entry.http_method] ?? 'text-gray-400'}`}>
                      {entry.http_method}
                    </td>
                    <td className="px-4 py-2.5 text-gray-500 font-mono truncate max-w-xs">
                      {entry.path}
                    </td>
                    <td className={`px-4 py-2.5 font-mono font-bold ${STATUS_COLOR(entry.status_code)}`}>
                      {entry.status_code ?? '—'}
                    </td>
                    <td className="px-4 py-2.5 text-gray-500 font-mono whitespace-nowrap">
                      {entry.ip_address ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 text-sm bg-gray-900 border border-gray-800 rounded-lg text-gray-400 hover:text-white disabled:opacity-40 transition-colors"
          >
            Previous
          </button>
          <span className="text-sm text-gray-500">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-4 py-2 text-sm bg-gray-900 border border-gray-800 rounded-lg text-gray-400 hover:text-white disabled:opacity-40 transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
