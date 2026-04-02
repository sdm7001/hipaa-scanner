import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { format } from 'date-fns'
import { ChevronRight, Clock, CheckCircle, AlertCircle } from 'lucide-react'
import clsx from 'clsx'

interface Scan {
  id: string
  client_id: string
  client_name?: string
  started_at: string
  completed_at: string | null
  overall_score: number | null
  risk_level: string | null
  targets_scanned: number
  targets_failed: number
  critical_count: number
  high_count: number
}

function RiskBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-gray-600 text-xs">—</span>
  const map: Record<string, string> = {
    MINIMAL: 'bg-green-900/30 text-green-400 border border-green-800/50',
    LOW: 'bg-green-900/20 text-green-500 border border-green-900/50',
    MODERATE: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800/50',
    ELEVATED: 'bg-orange-900/30 text-orange-400 border border-orange-800/50',
    HIGH: 'bg-red-900/30 text-red-400 border border-red-800/50',
  }
  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', map[level] ?? 'bg-gray-800 text-gray-400')}>
      {level}
    </span>
  )
}

export default function Scans() {
  const { data: scans, isLoading } = useQuery<Scan[]>({
    queryKey: ['scans'],
    queryFn: async () => (await api.get('/scans/')).data,
    refetchInterval: 30_000,
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-white">Scans</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Scans are initiated from the CLI scanner tool and uploaded automatically.
        </p>
      </div>

      {/* CLI hint */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <p className="text-xs font-medium text-gray-400 mb-2">Run a scan from the CLI</p>
        <pre className="text-xs text-green-400 bg-gray-950 rounded-lg px-3 py-2 overflow-x-auto">{`hipaa-scanner scan \\
  --targets 192.168.1.0/24 \\
  --username DOMAIN\\\\admin \\
  --password "pass" \\
  --client-id <CLIENT_ID> \\
  --api-key <MSP_API_KEY>`}</pre>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">
              <th className="text-left px-4 py-3 font-medium">Client</th>
              <th className="text-left px-4 py-3 font-medium">Date</th>
              <th className="text-left px-4 py-3 font-medium">Score</th>
              <th className="text-left px-4 py-3 font-medium">Risk</th>
              <th className="text-left px-4 py-3 font-medium">Findings</th>
              <th className="text-left px-4 py-3 font-medium">Targets</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i}>
                <td colSpan={7} className="px-4 py-3">
                  <div className="h-5 bg-gray-800 rounded animate-pulse w-2/3" />
                </td>
              </tr>
            ))}
            {!isLoading && (!scans || scans.length === 0) && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-600">
                  No scans yet. Run your first scan from the CLI tool.
                </td>
              </tr>
            )}
            {scans?.map((s) => (
              <tr
                key={s.id}
                className="hover:bg-gray-800/40 cursor-pointer group transition-colors"
                onClick={() => window.location.hash = `/scans/${s.id}`}
              >
                <td className="px-4 py-3 text-white font-medium">{s.client_name ?? s.client_id.slice(0, 8)}</td>
                <td className="px-4 py-3 text-gray-400 text-xs">
                  {s.completed_at
                    ? format(new Date(s.completed_at), 'MMM d, yyyy HH:mm')
                    : <span className="flex items-center gap-1 text-yellow-500"><Clock className="w-3 h-3" />Running</span>
                  }
                </td>
                <td className="px-4 py-3">
                  {s.overall_score !== null
                    ? <span className={clsx('font-bold', s.overall_score >= 90 ? 'text-green-400' : s.overall_score >= 70 ? 'text-yellow-400' : 'text-red-400')}>
                        {s.overall_score.toFixed(0)}
                      </span>
                    : <span className="text-gray-600">—</span>
                  }
                </td>
                <td className="px-4 py-3"><RiskBadge level={s.risk_level} /></td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 text-xs">
                    {s.critical_count > 0 && (
                      <span className="flex items-center gap-1 text-red-400">
                        <AlertCircle className="w-3 h-3" />{s.critical_count} critical
                      </span>
                    )}
                    {s.high_count > 0 && (
                      <span className="flex items-center gap-1 text-orange-400">
                        <AlertCircle className="w-3 h-3" />{s.high_count} high
                      </span>
                    )}
                    {s.critical_count === 0 && s.high_count === 0 && (
                      <span className="flex items-center gap-1 text-green-400">
                        <CheckCircle className="w-3 h-3" />None
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-400 text-xs">{s.targets_scanned} scanned</td>
                <td className="px-4 py-3 text-right">
                  <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-400 ml-auto" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
