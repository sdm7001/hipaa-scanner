import { useQuery } from '@tanstack/react-query'
import { FileText, Download, TrendingUp, TrendingDown, Minus, AlertTriangle } from 'lucide-react'
import { api } from '@/lib/api'

interface Client {
  id: string
  name: string
}

interface Scan {
  id: string
  client_id: string
  overall_score: number | null
  risk_level: string | null
  completed_at: string | null
  findings_critical: number
  findings_high: number
  findings_medium: number
  findings_low: number
  hosts_scanned: number
}

function riskColor(level: string | null) {
  switch (level?.toUpperCase()) {
    case 'MINIMAL': return 'text-green-400'
    case 'LOW': return 'text-blue-400'
    case 'MODERATE': return 'text-yellow-400'
    case 'ELEVATED': return 'text-orange-400'
    case 'HIGH': return 'text-red-400'
    default: return 'text-gray-400'
  }
}

function ScoreTrend({ scans }: { scans: Scan[] }) {
  if (scans.length < 2) return <Minus className="w-4 h-4 text-gray-500" />
  const latest = scans[0].overall_score ?? 0
  const prev = scans[1].overall_score ?? 0
  const diff = latest - prev
  if (diff > 2) return <span className="flex items-center gap-1 text-green-400 text-xs"><TrendingUp className="w-3.5 h-3.5" />+{diff.toFixed(1)}</span>
  if (diff < -2) return <span className="flex items-center gap-1 text-red-400 text-xs"><TrendingDown className="w-3.5 h-3.5" />{diff.toFixed(1)}</span>
  return <span className="text-gray-500 text-xs">stable</span>
}

function ClientReportRow({ client, scans }: { client: Client; scans: Scan[] }) {
  const latestScan = scans[0]
  if (!latestScan) return null

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="font-semibold text-white truncate">{client.name}</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            {scans.length} scan{scans.length !== 1 ? 's' : ''} ·{' '}
            Last: {latestScan.completed_at ? new Date(latestScan.completed_at).toLocaleDateString() : 'N/A'}
          </p>
        </div>
        <div className="flex items-center gap-6 flex-shrink-0">
          <div className="text-right">
            <p className="text-2xl font-bold text-white">{latestScan.overall_score?.toFixed(0) ?? '—'}</p>
            <p className={`text-xs font-medium ${riskColor(latestScan.risk_level)}`}>{latestScan.risk_level ?? '—'}</p>
          </div>
          <ScoreTrend scans={scans} />
        </div>
      </div>

      {/* Findings breakdown */}
      <div className="mt-4 flex items-center gap-4 text-xs">
        {latestScan.findings_critical > 0 && (
          <span className="flex items-center gap-1 text-red-400 font-medium">
            <AlertTriangle className="w-3 h-3" />{latestScan.findings_critical} Critical
          </span>
        )}
        {latestScan.findings_high > 0 && (
          <span className="text-orange-400">{latestScan.findings_high} High</span>
        )}
        {latestScan.findings_medium > 0 && (
          <span className="text-yellow-400">{latestScan.findings_medium} Medium</span>
        )}
        {latestScan.findings_low > 0 && (
          <span className="text-gray-400">{latestScan.findings_low} Low</span>
        )}
      </div>

      {/* Score history bar (last 5 scans) */}
      {scans.length > 1 && (
        <div className="mt-4">
          <p className="text-[11px] text-gray-600 mb-1.5">Score trend (last {Math.min(scans.length, 5)} scans)</p>
          <div className="flex items-end gap-1 h-8">
            {scans.slice(0, 5).reverse().map((s, i) => {
              const score = s.overall_score ?? 0
              const height = `${Math.max(10, score)}%`
              const color = score >= 80 ? 'bg-green-500' : score >= 65 ? 'bg-yellow-500' : 'bg-red-500'
              return (
                <div key={i} className="flex-1 flex flex-col justify-end" title={`${score.toFixed(0)} — ${s.completed_at ? new Date(s.completed_at).toLocaleDateString() : 'N/A'}`}>
                  <div className={`${color} rounded-sm opacity-70 hover:opacity-100 transition-opacity`} style={{ height }} />
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="mt-4 flex items-center gap-3">
        <button
          onClick={() => { window.location.hash = `/scans/${latestScan.id}` }}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          View Latest Scan →
        </button>
        <button
          onClick={() => {
            api.post(`/reports/${latestScan.id}/generate`, { report_type: 'executive' }, { responseType: 'blob' })
              .then(res => {
                const url = URL.createObjectURL(res.data)
                const a = document.createElement('a')
                a.href = url
                a.download = `hipaa-report-${client.name.replace(/\s+/g, '-')}-${latestScan.id.slice(0, 8)}.pdf`
                a.click()
                URL.revokeObjectURL(url)
              })
              .catch(() => alert('Report generation failed'))
          }}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors"
        >
          <Download className="w-3 h-3" /> PDF Report
        </button>
      </div>
    </div>
  )
}

export default function Reports() {
  const { data: clients = [], isLoading: clientsLoading } = useQuery<Client[]>({
    queryKey: ['clients'],
    queryFn: async () => (await api.get('/clients/')).data,
  })

  const { data: allScans = [], isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ['all-scans'],
    queryFn: async () => (await api.get('/scans/')).data,
  })

  const loading = clientsLoading || scansLoading

  // Group scans by client, most recent first
  const scansByClient = allScans.reduce<Record<string, Scan[]>>((acc, s) => {
    if (!acc[s.client_id]) acc[s.client_id] = []
    acc[s.client_id].push(s)
    return acc
  }, {})
  for (const id in scansByClient) {
    scansByClient[id].sort((a, b) =>
      new Date(b.completed_at ?? 0).getTime() - new Date(a.completed_at ?? 0).getTime()
    )
  }

  const clientsWithScans = clients.filter(c => scansByClient[c.id]?.length > 0)
  const clientsWithoutScans = clients.filter(c => !scansByClient[c.id]?.length)

  // Portfolio summary
  const allLatestScans = clientsWithScans.map(c => scansByClient[c.id][0])
  const avgScore = allLatestScans.length
    ? allLatestScans.reduce((s, sc) => s + (sc.overall_score ?? 0), 0) / allLatestScans.length
    : null
  const criticalClients = allLatestScans.filter(s => s.risk_level === 'HIGH' || s.risk_level === 'ELEVATED').length

  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-36 bg-gray-900 border border-gray-800 rounded-xl animate-pulse" />
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Reports</h1>
        <p className="text-sm text-gray-400 mt-1">HIPAA compliance status across all clients</p>
      </div>

      {/* Portfolio summary */}
      {clientsWithScans.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide">Portfolio Score</p>
            <p className="text-2xl font-bold text-white mt-1">{avgScore?.toFixed(1) ?? '—'}</p>
            <p className="text-xs text-gray-500 mt-0.5">avg across {clientsWithScans.length} clients</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide">At-Risk Clients</p>
            <p className={`text-2xl font-bold mt-1 ${criticalClients > 0 ? 'text-red-400' : 'text-green-400'}`}>{criticalClients}</p>
            <p className="text-xs text-gray-500 mt-0.5">elevated or high risk</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide">Total Scans</p>
            <p className="text-2xl font-bold text-white mt-1">{allScans.length}</p>
            <p className="text-xs text-gray-500 mt-0.5">across all clients</p>
          </div>
        </div>
      )}

      {/* Client report cards */}
      {clientsWithScans.length === 0 && (
        <div className="text-center py-20">
          <FileText className="w-10 h-10 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-400">No scan data yet</p>
          <p className="text-sm text-gray-600 mt-1">Run your first scan to see reports here</p>
        </div>
      )}

      <div className="space-y-4">
        {clientsWithScans.map(client => (
          <ClientReportRow
            key={client.id}
            client={client}
            scans={scansByClient[client.id]}
          />
        ))}
      </div>

      {clientsWithoutScans.length > 0 && (
        <div>
          <p className="text-xs text-gray-600 uppercase tracking-wide mb-2">Clients awaiting first scan</p>
          <div className="flex flex-wrap gap-2">
            {clientsWithoutScans.map(c => (
              <span key={c.id} className="text-xs bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-gray-400">
                {c.name}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
