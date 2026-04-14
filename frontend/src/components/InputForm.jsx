import React, { useState } from 'react'
import { Link, Mail, Search, Loader2 } from 'lucide-react'
import clsx from 'clsx'

const SAMPLE_PHISHING_URL = 'http://192.168.99.1/paypal/login'
const SAMPLE_PHISHING_EMAIL = `From: security@paypa1-alerts.com
Reply-To: harvest@evil-collector.net
Subject: URGENT: Your PayPal account has been suspended

Your account will be suspended. Verify your account immediately.
Action required: click here https://fake-paypal.com/verify`

export default function InputForm({ onAnalyze, loading }) {
  const [tab, setTab] = useState('url')
  const [url, setUrl] = useState('')
  const [email, setEmail] = useState('')

  const handleSubmit = () => {
    if (tab === 'url' && url.trim()) {
      onAnalyze({ type: 'url', value: url.trim() })
    } else if (tab === 'email' && email.trim()) {
      onAnalyze({ type: 'email', value: email.trim() })
    }
  }

  const canSubmit = tab === 'url' ? url.trim().length > 0 : email.trim().length > 0

  return (
    <div className="card space-y-4">
      {/* Tab switcher */}
      <div className="flex gap-1 p-1 bg-slate-900 rounded-lg w-fit">
        {[
          { id: 'url', label: 'URL', icon: Link },
          { id: 'email', label: 'Email', icon: Mail },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all',
              tab === id
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200'
            )}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {/* URL input */}
      {tab === 'url' && (
        <div className="space-y-2">
          <label className="text-xs text-slate-400 uppercase tracking-wider">
            URL to analyze
          </label>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="https://suspicious-domain.com/login"
            className="w-full bg-slate-900 border border-phish-border rounded-lg px-4 py-3
                       text-slate-100 placeholder-slate-600 font-mono text-sm
                       focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          <button
            onClick={() => setUrl(SAMPLE_PHISHING_URL)}
            className="text-xs text-slate-500 hover:text-blue-400 underline"
          >
            Load sample phishing URL
          </button>
        </div>
      )}

      {/* Email input */}
      {tab === 'email' && (
        <div className="space-y-2">
          <label className="text-xs text-slate-400 uppercase tracking-wider">
            Raw email (paste full RFC 2822 content)
          </label>
          <textarea
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder={'From: attacker@evil.com\nSubject: Urgent action required\n\nPaste full email here...'}
            rows={8}
            className="w-full bg-slate-900 border border-phish-border rounded-lg px-4 py-3
                       text-slate-100 placeholder-slate-600 font-mono text-sm resize-y
                       focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          <button
            onClick={() => setEmail(SAMPLE_PHISHING_EMAIL)}
            className="text-xs text-slate-500 hover:text-blue-400 underline"
          >
            Load sample phishing email
          </button>
        </div>
      )}

      {/* Submit */}
      <button
        onClick={handleSubmit}
        disabled={!canSubmit || loading}
        className="btn-primary w-full flex items-center justify-center gap-2"
      >
        {loading ? (
          <>
            <Loader2 size={16} className="animate-spin" />
            Analyzing...
          </>
        ) : (
          <>
            <Search size={16} />
            Analyze {tab === 'url' ? 'URL' : 'Email'}
          </>
        )}
      </button>
    </div>
  )
}
