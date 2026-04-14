import React, { useEffect, useState } from 'react'
import { getHealth } from '../api/client'
import { CheckCircle, XCircle, AlertCircle } from 'lucide-react'

function StatusDot({ ok, label }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      {ok === true  && <CheckCircle size={12} className="text-green-400" />}
      {ok === false && <XCircle    size={12} className="text-red-400"   />}
      {ok === null  && <AlertCircle size={12} className="text-slate-500" />}
      <span className={ok === true ? 'text-slate-300' : ok === false ? 'text-red-400' : 'text-slate-500'}>
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
      <div className="flex items-center gap-2 text-xs text-slate-600">
        <AlertCircle size={12} />
        Connecting to backend...
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
        <span className="text-xs text-slate-600 ml-auto">
          uptime {Math.floor(health.uptime_s / 60)}m {Math.floor(health.uptime_s % 60)}s
        </span>
      )}
    </div>
  )
}
