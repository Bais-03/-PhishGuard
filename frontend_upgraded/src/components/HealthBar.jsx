import React, { useEffect, useState } from 'react'
import { getHealth } from '../api/client'
import { CheckCircle, XCircle, AlertCircle, Activity } from 'lucide-react'

function StatusDot({ ok, label }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      {ok === true && <CheckCircle size={12} className="text-safe-500" />}
      {ok === false && <XCircle size={12} className="text-danger-500" />}
      {ok === null && <AlertCircle size={12} className="text-warning-500" />}
      <span className={ok === true ? 'text-text-primary' : ok === false ? 'text-danger-400' : 'text-warning-400'}>
        {label}
      </span>
    </div>
  )
}

export default function HealthBar() {
  const [health, setHealth] = useState(null)

  useEffect(() => {
    const fetch = () => getHealth().then(setHealth).catch(() => setHealth(null))
    fetch()
    const id = setInterval(fetch, 15000)
    return () => clearInterval(id)
  }, [])

  if (!health) {
    return (
      <div className="flex items-center gap-2 text-xs text-text-muted">
        <Activity size={12} className="animate-pulse text-accent-400" />
        <span>Connecting to backend...</span>
      </div>
    )
  }

  return (
    <div className="flex flex-wrap items-center gap-4">
      <StatusDot ok={health.redis === 'ok'} label="Redis" />
      <StatusDot ok={health.vt_api === 'configured'} label="VirusTotal" />
      <StatusDot ok={health.gsb_api === 'configured'} label="Safe Browsing" />
      <StatusDot ok={health.abuseipdb === 'configured'} label="AbuseIPDB" />
      {health.uptime_s !== undefined && (
        <div className="flex items-center gap-1 text-xs text-text-muted ml-auto">
          <Activity size={10} className="text-accent-400" />
          <span>uptime {Math.floor(health.uptime_s / 60)}m {Math.floor(health.uptime_s % 60)}s</span>
        </div>
      )}
    </div>
  )
}