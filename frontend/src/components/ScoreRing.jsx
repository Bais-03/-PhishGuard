import React, { useEffect, useRef } from 'react'

const RADIUS = 48
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function getColor(score) {
  if (score >= 65) return '#EF4444'   // red
  if (score >= 35) return '#F59E0B'   // amber
  return '#22C55E'                     // green
}

function getVerdict(verdict) {
  if (verdict === 'PHISHING') return { label: 'PHISHING', color: 'text-red-400' }
  if (verdict === 'SUSPICIOUS') return { label: 'SUSPICIOUS', color: 'text-amber-400' }
  return { label: 'LIKELY SAFE', color: 'text-green-400' }
}

export default function ScoreRing({ score, verdict }) {
  const dashOffset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE
  const color = getColor(score)
  const v = getVerdict(verdict)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 112 112">
          {/* Background track */}
          <circle
            cx="56" cy="56" r={RADIUS}
            fill="none"
            stroke="#334155"
            strokeWidth="8"
          />
          {/* Score arc */}
          <circle
            cx="56" cy="56" r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={dashOffset}
            style={{ transition: 'stroke-dashoffset 1s ease-out, stroke 0.3s' }}
          />
        </svg>
        {/* Score number in center */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold font-mono" style={{ color }}>
            {score}
          </span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
      </div>
      <span className={`text-lg font-bold tracking-widest ${v.color}`}>
        {v.label}
      </span>
    </div>
  )
}
