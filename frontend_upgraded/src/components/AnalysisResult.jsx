import React from 'react'
import { Clock, Database, Shield } from 'lucide-react'
import ScoreRing from './ScoreRing'
import FlagBreakdown from './FlagBreakdown'
import { Card } from './ui'

function VerdictBanner({ verdict, score }) {
  const config = {
    'PHISHING': { 
      bg: 'bg-danger-500/10 border-danger-500/30', 
      text: 'text-danger-400', 
      icon: '🔴',
      msg: 'This is almost certainly a phishing attempt. Do not interact with this content.' 
    },
    'SUSPICIOUS': { 
      bg: 'bg-warning-500/10 border-warning-500/30', 
      text: 'text-warning-400', 
      icon: '🟡',
      msg: 'Suspicious indicators detected. Proceed with extreme caution.' 
    },
    'LIKELY SAFE': { 
      bg: 'bg-safe-500/10 border-safe-500/30', 
      text: 'text-safe-400', 
      icon: '🟢',
      msg: 'No significant phishing indicators detected.' 
    },
  }
  const c = config[verdict] || config['LIKELY SAFE']

  return (
    <div className={`rounded-xl border p-4 ${c.bg}`}>
      <p className={`text-sm ${c.text}`}>
        <span className="mr-2">{c.icon}</span>
        {c.msg}
      </p>
    </div>
  )
}

export default function AnalysisResult({ result }) {
  if (!result) return null

  const { score, verdict, flags = [], reasons = [], duration_ms, cache_hit, input_type } = result
  const analyzedAt = result.analyzed_at
    ? new Date(result.analyzed_at).toLocaleTimeString()
    : 'just now'

  const safeReasons = Array.isArray(reasons) 
    ? reasons.map(r => typeof r === 'string' ? r : String(r))
    : []

  return (
    <div className="space-y-5">
      {/* Score + Verdict */}
      <Card className="flex flex-col sm:flex-row items-center gap-6">
        <ScoreRing score={score} verdict={verdict} />
        <div className="flex-1 space-y-3">
          <VerdictBanner verdict={verdict} score={score} />

          {/* Top Reasons */}
          {safeReasons.length > 0 && (
            <div>
              <p className="text-xs text-accent-400 uppercase tracking-wider mb-2">Top Reasons</p>
              <ul className="space-y-1">
                {safeReasons.slice(0, 5).map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                    <span className="text-accent-400 font-mono mt-0.5">{i + 1}.</span>
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Meta */}
          <div className="flex flex-wrap gap-4 text-xs text-accent-400 pt-1">
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
      </Card>

      {/* Flag Breakdown */}
      {flags && flags.length > 0 && (
        <Card>
          <FlagBreakdown flags={flags} />
        </Card>
      )}
    </div>
  )
}