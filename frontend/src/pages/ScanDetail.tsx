import { useQuery, useMutation } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { format } from 'date-fns'
import { Download, ArrowLeft, AlertCircle, CheckCircle, AlertTriangle, Info } from 'lucide-react'
import clsx from 'clsx'

interface Finding {
  id: string
  check_id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  result: 'fail' | 'pass' | 'warn' | 'error'
  category: string
  remediation: string | null
  affected_targets: string[]
  status: string
}

interface CategoryScore {
  category: string
  score: number
  max_score: number
  findings_count: number
}

interface ScanDetail {
  id: string
  client_id: string
  client_name?: string
  started_at: string
  completed_at: string | null
  overall_score: number | null
  risk_level: string | null
  targets_scanned: number
  targets_failed: number
  scanner_version: string
  environment_type: string
  findings: Finding[]
  category_scores: CategoryScore[]
}

const SEVERITY_CONFIG = {
  critical: { color: 'text-red-400', bg: 'bg-red-900/20 border-red-800/50', icon: AlertCircle, label: 'Critical' },
  high: { color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800/50', icon: AlertCircle, label: 'High' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800/50', icon: AlertTriangle, label: 'Medium' },
  low: { color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800/50', icon: Info, label: 'Low' },
  info: { color: 'text-gray-400', bg: 'bg-gray-900/50 border-gray-700/50', icon: Info, label: 'Info' },
}

function FindingCard({ f }: { f: Finding }) {
  if (f.result === 'pass') return null
  const cfg = SEVERITY_CONFIG[f.severity] ?? SEVERITY_CONFIG.low
  const Icon = cfg.icon
  return (
    <div className={clsx('rounded-lg border p-4 space-y-2', cfg.bg)}>
      <div className="flex items-start gap-3">
        <Icon className={clsx('w-4 h-4 mt-0.5 flex-shrink-0', cfg.color)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={clsx('text-xs font-semibold uppercase tracking-wide', cfg.color)}>{cfg.label}</span>
            <span className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{f.category}</span>
          </div>
          <p className="text-sm font-medium text-white mt-1">{f.title}</p>
          <p className="text-xs text-gray-400 mt-1 leading-relaxed">{f.description}</p>
          {f.remediation && (
            <div className="mt-2 pt-2 border-t border-gray-700/50">
              <p className="text-xs text-gray-500 font-medium mb-0.5">Remediation</p>
              <p className="text-xs text-gray-400">{f.remediation}</p>
            </div>
          )}
          {f.affected_targets?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {f.affected_targets.slice(0, 5).map((t) => (
                <span key={t} className="text-[11px] bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded font-mono">{t}</span>
              ))}
              {f.affected_targets.length > 5 && (
                <span className="text-[11px] text-gray-600">+{f.affected_targets.length - 5} more</span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function ScanDetail({ scanId }: { scanId: string }) {
  const { data: scan, isLoading } = useQuery<ScanDetail>({
    queryKey: ['scan', scanId],
    queryFn: async () => (await api.get(`/scans/${scanId}`)).data,
  })

  const pdfMutation = useMutation({
    mutationFn: (type: 'executive' | 'technical') =>
      api.post(`/reports/${scanId}/generate?report_type=${type}`, {}, { responseType: 'blob' }),
    onSuccess: (resp, type) => {
      const url = URL.createObjectURL(new Blob([resp.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `hipaa-report-${type}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    },
  })

  if (isLoading) {
    return (
      <div className="space-y-3">
        {[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-gray-900 rounded-xl animate-pulse" />)}
      </div>
    )
  }

  if (!scan) return <p className="text-gray-500 text-sm">Scan not found.</p>

  const failedFindings = scan.findings.filter(f => f.result !== 'pass')
  const bySeverity = ['critical', 'high', 'medium', 'low', 'info'] as const
  const scoreColor = !scan.overall_score ? 'text-gray-400'
    : scan.overall_score >= 90 ? 'text-green-400'
    : scan.overall_score >= 70 ? 'text-yellow-400'
    : 'text-red-400'

  return (
    <div className="space-y-5">
      {/* Back */}
      <button onClick={() => window.location.hash = '/scans'} className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-white transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to Scans
      </button>

      {/* Header */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <p className="text-xs text-gray-500 mb-1">Scan Report</p>
            <h1 className="text-lg font-semibold text-white">{scan.client_name ?? 'Unknown Client'}</h1>
            {scan.completed_at && (
              <p className="text-xs text-gray-500 mt-1">{format(new Date(scan.completed_at), "MMMM d, yyyy 'at' h:mm a")}</p>
            )}
            <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 flex-wrap">
              <span>{scan.targets_scanned} targets scanned</span>
              {scan.targets_failed > 0 && <span className="text-orange-400">{scan.targets_failed} failed</span>}
              <span className="capitalize">{scan.environment_type.replace('_', ' ')}</span>
              <span>v{scan.scanner_version}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => pdfMutation.mutate('executive')}
              disabled={pdfMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-60 rounded-lg transition-colors"
            >
              <Download className="w-3.5 h-3.5" />Executive PDF
            </button>
            <button
              onClick={() => pdfMutation.mutate('technical')}
              disabled={pdfMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-300 bg-gray-800 hover:bg-gray-700 disabled:opacity-60 rounded-lg transition-colors"
            >
              <Download className="w-3.5 h-3.5" />Technical PDF
            </button>
          </div>
        </div>

        {/* Score */}
        <div className="mt-5 flex items-center gap-6 flex-wrap">
          <div>
            <p className="text-xs text-gray-500 mb-1">Overall Score</p>
            <p className={clsx('text-4xl font-bold', scoreColor)}>
              {scan.overall_score?.toFixed(0) ?? '—'}
              <span className="text-sm text-gray-500 ml-1">/100</span>
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Risk Level</p>
            <p className="text-lg font-semibold text-white capitalize">{scan.risk_level ?? '—'}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1">Findings</p>
            <p className="text-lg font-semibold text-white">{failedFindings.length}</p>
          </div>
        </div>
      </div>

      {/* Category scores */}
      {scan.category_scores?.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Category Scores</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {scan.category_scores.map((cs) => {
              const pct = cs.max_score > 0 ? (cs.score / cs.max_score) * 100 : 0
              const barColor = pct >= 90 ? 'bg-green-500' : pct >= 70 ? 'bg-yellow-500' : pct >= 50 ? 'bg-orange-500' : 'bg-red-500'
              return (
                <div key={cs.category} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-400">{cs.category}</span>
                    <span className="text-gray-500">{cs.score}/{cs.max_score}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div className={clsx('h-full rounded-full transition-all', barColor)} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Findings */}
      <div>
        <h2 className="text-sm font-semibold text-white mb-3">
          Findings <span className="text-gray-500 font-normal">({failedFindings.length})</span>
        </h2>
        {failedFindings.length === 0
          ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
              <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-2" />
              <p className="text-sm text-green-400 font-medium">All checks passed</p>
              <p className="text-xs text-gray-600 mt-1">No compliance issues found in this scan.</p>
            </div>
          )
          : (
            <div className="space-y-2">
              {bySeverity.map((sev) => {
                const group = failedFindings.filter(f => f.severity === sev)
                if (group.length === 0) return null
                return (
                  <div key={sev}>
                    <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5 mt-3">{sev} ({group.length})</p>
                    <div className="space-y-2">
                      {group.map((f) => <FindingCard key={f.id} f={f} />)}
                    </div>
                  </div>
                )
              })}
            </div>
          )
        }
      </div>
    </div>
  )
}
