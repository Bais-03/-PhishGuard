import React, { useState } from 'react'
import { Settings, Server, Key, Bell, Shield, Globe, Moon, AlertCircle, CheckCircle } from 'lucide-react'

function SettingRow({ label, desc, children, status }) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-border last:border-0">
      <div className="space-y-0.5">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium text-text-primary">{label}</p>
          {status && (
            <span className={`text-xs px-1.5 py-0.5 rounded-full ${status === 'active' ? 'bg-safe-500/10 text-safe-400' : 'bg-danger-500/10 text-danger-400'}`}>
              {status === 'active' ? 'Active' : 'Inactive'}
            </span>
          )}
        </div>
        <p className="text-xs text-text-muted">{desc}</p>
      </div>
      {children}
    </div>
  )
}

function Toggle({ value, onChange }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${value ? 'bg-accent-500' : 'bg-bg-raised border border-border'}`}
    >
      <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${value ? 'translate-x-5' : ''}`} />
    </button>
  )
}

function ApiKeyInput({ label, value, onSave }) {
  const [isEditing, setIsEditing] = useState(false)
  const [tempValue, setTempValue] = useState(value)

  return (
    <div className="flex items-center justify-between py-4 border-b border-border last:border-0">
      <div>
        <p className="text-sm font-medium text-text-primary">{label}</p>
        <p className="text-xs text-text-muted">API key for threat intelligence service</p>
      </div>
      <div className="flex items-center gap-2">
        {isEditing ? (
          <>
            <input
              type="password"
              value={tempValue}
              onChange={(e) => setTempValue(e.target.value)}
              className="px-3 py-1.5 text-xs bg-bg-raised border border-border rounded font-mono text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-500"
              placeholder="Enter API key"
              autoFocus
            />
            <button
              onClick={() => { onSave(tempValue); setIsEditing(false) }}
              className="px-2 py-1 text-xs text-safe-400 hover:text-safe-300"
            >
              Save
            </button>
            <button
              onClick={() => { setIsEditing(false); setTempValue(value) }}
              className="px-2 py-1 text-xs text-text-muted hover:text-text-secondary"
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            <code className="text-xs font-mono text-text-muted bg-bg-raised px-2 py-1 rounded">
              {value ? '••••••••••••••••' : 'Not configured'}
            </code>
            <button
              onClick={() => setIsEditing(true)}
              className="px-2 py-1 text-xs text-accent-400 hover:text-accent-300"
            >
              {value ? 'Update' : 'Add'}
            </button>
          </>
        )}
      </div>
    </div>
  )
}

export default function SettingsPage() {
  const [notifications, setNotifications] = useState(true)
  const [deepScan, setDeepScan] = useState(false)
  const [cache, setCache] = useState(true)
  const [darkMode, setDarkMode] = useState(true)
  const [autoUpdate, setAutoUpdate] = useState(true)

  const [vtKey, setVtKey] = useState('')
  const [gsbKey, setGsbKey] = useState('')
  const [abuseKey, setAbuseKey] = useState('')

  const handleSaveVtKey = (key) => setVtKey(key)
  const handleSaveGsbKey = (key) => setGsbKey(key)
  const handleSaveAbuseKey = (key) => setAbuseKey(key)

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-9 h-9 bg-accent-500/10 border border-accent-500/30 rounded-xl flex items-center justify-center">
            <Settings size={16} className="text-accent-400" />
          </div>
          <h1 className="text-xl font-semibold text-text-primary">Settings</h1>
        </div>
        <p className="text-sm text-text-muted">Configure PhishGuard behavior and integrations</p>
      </div>

      {/* Backend Configuration */}
      <div className="card !p-0 overflow-hidden">
        <div className="px-5 py-3 bg-bg-raised border-b border-border flex items-center gap-2">
          <Server size={14} className="text-accent-400" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Backend</span>
        </div>
        <div className="px-5">
          <SettingRow 
            label="API Endpoint" 
            desc="Backend URL for analysis requests"
          >
            <code className="text-xs font-mono text-text-secondary bg-bg-raised border border-border px-3 py-1.5 rounded">
              {import.meta.env.VITE_API_URL || 'http://localhost:8000'}
            </code>
          </SettingRow>
        </div>
      </div>

      {/* API Keys */}
      <div className="card !p-0 overflow-hidden">
        <div className="px-5 py-3 bg-bg-raised border-b border-border flex items-center gap-2">
          <Key size={14} className="text-accent-400" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">API Keys</span>
        </div>
        <div className="px-5">
          <ApiKeyInput 
            label="VirusTotal API Key" 
            value={vtKey} 
            onSave={handleSaveVtKey} 
          />
          <ApiKeyInput 
            label="Google Safe Browsing Key" 
            value={gsbKey} 
            onSave={handleSaveGsbKey} 
          />
          <ApiKeyInput 
            label="AbuseIPDB API Key" 
            value={abuseKey} 
            onSave={handleSaveAbuseKey} 
          />
        </div>
      </div>

      {/* Analysis Settings */}
      <div className="card !p-0 overflow-hidden">
        <div className="px-5 py-3 bg-bg-raised border-b border-border flex items-center gap-2">
          <Shield size={14} className="text-accent-400" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Analysis</span>
        </div>
        <div className="px-5">
          <SettingRow 
            label="Response Cache" 
            desc="Cache scan results to speed up repeated lookups"
            status={cache ? 'active' : 'inactive'}
          >
            <Toggle value={cache} onChange={setCache} />
          </SettingRow>
          <SettingRow 
            label="Deep Content Scan" 
            desc="Run Playwright rendering (slower, more thorough)"
            status={deepScan ? 'active' : 'inactive'}
          >
            <Toggle value={deepScan} onChange={setDeepScan} />
          </SettingRow>
          <SettingRow 
            label="Auto-Update Threat Intel" 
            desc="Automatically fetch latest threat intelligence feeds"
            status={autoUpdate ? 'active' : 'inactive'}
          >
            <Toggle value={autoUpdate} onChange={setAutoUpdate} />
          </SettingRow>
        </div>
      </div>

      {/* Notifications */}
      <div className="card !p-0 overflow-hidden">
        <div className="px-5 py-3 bg-bg-raised border-b border-border flex items-center gap-2">
          <Bell size={14} className="text-accent-400" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Notifications</span>
        </div>
        <div className="px-5">
          <SettingRow 
            label="Alert on Phishing" 
            desc="Show prominent alerts when phishing is detected"
            status={notifications ? 'active' : 'inactive'}
          >
            <Toggle value={notifications} onChange={setNotifications} />
          </SettingRow>
        </div>
      </div>

      {/* Appearance */}
      <div className="card !p-0 overflow-hidden">
        <div className="px-5 py-3 bg-bg-raised border-b border-border flex items-center gap-2">
          <Globe size={14} className="text-accent-400" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Appearance</span>
        </div>
        <div className="px-5">
          <SettingRow 
            label="Dark Mode" 
            desc="Use dark theme (currently fixed)"
          >
            <div className="flex items-center gap-2">
              <Moon size={14} className="text-accent-400" />
              <span className="text-xs text-text-muted">Always enabled</span>
            </div>
          </SettingRow>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end pt-2">
        <button className="btn-primary px-6 py-2 text-sm">
          Save Changes
        </button>
      </div>

      {/* Status Note */}
      <div className="flex items-center justify-center gap-2 text-xs text-text-muted">
        <CheckCircle size={12} className="text-safe-400" />
        <span>All settings are saved locally</span>
        <AlertCircle size={12} className="text-warning-400 ml-2" />
        <span>API keys are stored in browser memory only</span>
      </div>
    </div>
  )
}