import React from 'react'
import { Clock, Database, Shield } from 'lucide-react'
import ScoreRing from './ScoreRing'
import FlagBreakdown from './FlagBreakdown'

function VerdictBanner({ verdict, score }) {
  const config = {
    'PHISHING':    { bg: 'bg-red-950 border-red-700',   text: 'text-red-300',   msg: 'This is almost certainly a phishing attempt. Do not interact with this content.' },
    'SUSPICIOUS':  { bg: 'bg-amber-950 border-amber-700', text: 'text-amber-300', msg: 'Suspicious indicators detected. Proceed with extreme caution.' },
    'LIKELY SAFE': { bg: 'bg-green-950 border-green-700', text: 'text-green-300', msg: 'No significant phishing indicators detected.' },
  }
  const c = config[verdict] || config['LIKELY SAFE']

  return (
    <div className={`rounded-xl border p-4 ${c.bg}`}>
      <p className={`text-sm ${c.text}`}>{c.msg}</p>
    </div>
  )
}

export default function AnalysisResult({ result }) {
  if (!result) return null

  const { score, verdict, flags = [], reasons = [], duration_ms, cache_hit, input_type } = result
  const analyzedAt = result.analyzed_at
    ? new Date(result.analyzed_at).toLocaleTimeString()
    : 'just now'

  return (
    <div className="space-y-5">
      {/* Score + Verdict */}
      <div className="card flex flex-col sm:flex-row items-center gap-6">
        <ScoreRing score={score} verdict={verdict} />
        <div className="flex-1 space-y-3">
          <VerdictBanner verdict={verdict} score={score} />

          {/* Top 3 Reasons */}
          {reasons.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Top Reasons</p>
              <ul className="space-y-1">
                {reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="text-slate-500 font-mono mt-0.5">{i + 1}.</span>
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Meta */}
          <div className="flex flex-wrap gap-4 text-xs text-slate-500 pt-1">
            <span className="flex items-center gap-1">
              <Clock size={12} />
              {duration_ms}ms
            </span>
            <span className="flex items-center gap-1">
              <Database size={12} />
              {cache_hit ? 'Cache hit' : 'Fresh scan'}
            </span>
            <span className="flex items-center gap-1">
              <Shield size={12} />
              {input_type === 'email' ? 'Email analysis' : 'URL analysis'}
            </span>
            <span>{analyzedAt}</span>
          </div>
        </div>
      </div>

      {/* Flag Breakdown */}
      {flags.length > 0 && (
        <div className="card">
          <FlagBreakdown flags={flags} />
        </div>
      )}
    </div>
  )
}
