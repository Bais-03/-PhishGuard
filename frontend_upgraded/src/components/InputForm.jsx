import React, { useState, useRef } from 'react'
import { Link, Mail, Upload, FileText, Forward } from 'lucide-react'
import clsx from 'clsx'
import { Button, Input, Card } from './ui'

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
  const [uploadMethod, setUploadMethod] = useState('paste')
  const fileInputRef = useRef(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [forwardEmail, setForwardEmail] = useState('analyze@phishguard.com')

  const handleSubmit = () => {
    if (tab === 'url' && url.trim()) {
      onAnalyze({ type: 'url', value: url.trim() })
    } else if (tab === 'email' && uploadMethod === 'paste' && email.trim()) {
      onAnalyze({ type: 'email', value: email.trim() })
    } else if (tab === 'email' && uploadMethod === 'file' && selectedFile) {
      onAnalyze({ type: 'email_file', value: selectedFile })
    }
  }

  const handleFileSelect = (e) => {
    const file = e.target.files[0]
    if (file && file.name.endsWith('.eml')) {
      setSelectedFile(file)
      const reader = new FileReader()
      reader.onload = (event) => {
        setEmail(event.target.result)
      }
      reader.readAsText(file)
    } else {
      alert('Please select a valid .eml file')
    }
  }

  const handlePasteChange = (e) => {
    setEmail(e.target.value)
    setSelectedFile(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const copyForwardAddress = () => {
    navigator.clipboard.writeText(forwardEmail)
    alert('Email address copied! Forward suspicious emails to this address.')
  }

  const canSubmit = () => {
    if (tab === 'url') return url.trim().length > 0
    if (tab === 'email' && uploadMethod === 'paste') return email.trim().length > 0
    if (tab === 'email' && uploadMethod === 'file') return selectedFile !== null
    return false
  }

  return (
    <Card className="space-y-4">
      {/* Tab switcher */}
      <div className="flex gap-1 p-1 bg-bg-raised rounded-lg w-full sm:w-fit border border-border">
        {[
          { id: 'url', label: 'URL', icon: Link },
          { id: 'email', label: 'Email', icon: Mail },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'flex-1 sm:flex-none flex items-center justify-center gap-2 px-3 sm:px-4 py-2 rounded-md text-sm font-medium transition-all duration-150',
              tab === id
                ? 'bg-accent-500 text-white shadow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-surface'
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
          <label className="text-xs text-text-secondary uppercase tracking-wider">
            URL to analyze
          </label>
          <Input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="https://suspicious-domain.com/login"
            inputClassName="font-mono text-sm"
          />
          <button
            onClick={() => setUrl(SAMPLE_PHISHING_URL)}
            className="text-xs text-accent-400 hover:text-accent-300 underline transition-colors"
          >
            Load sample phishing URL
          </button>
        </div>
      )}

      {/* Email input */}
      {tab === 'email' && (
        <div className="space-y-4">
          {/* Upload method selector */}
          <div className="flex gap-2 border-b border-border pb-2">
            <button
              onClick={() => setUploadMethod('paste')}
              className={clsx(
                'flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-all duration-150',
                uploadMethod === 'paste'
                  ? 'bg-accent-500 text-white'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-surface'
              )}
            >
              <FileText size={14} />
              Paste Email
            </button>
            <button
              onClick={() => setUploadMethod('file')}
              className={clsx(
                'flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-all duration-150',
                uploadMethod === 'file'
                  ? 'bg-accent-500 text-white'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-surface'
              )}
            >
              <Upload size={14} />
              Upload .eml File
            </button>
          </div>

          {/* Paste method */}
          {uploadMethod === 'paste' && (
            <div className="space-y-2">
              <label className="text-xs text-text-secondary uppercase tracking-wider">
                Raw email (paste full RFC 2822 content)
              </label>
              <textarea
                value={email}
                onChange={handlePasteChange}
                placeholder={'From: attacker@evil.com\nSubject: Urgent action required\n\nPaste full email here...'}
                rows={8}
                className="w-full bg-bg-raised border border-border rounded-button px-4 py-3 
                           text-text-primary placeholder-text-muted font-mono text-sm resize-y
                           focus:outline-none focus:ring-1 focus:ring-accent-500 focus:border-accent-500
                           transition-all duration-150"
              />
              <button
                onClick={() => setEmail(SAMPLE_PHISHING_EMAIL)}
                className="text-xs text-accent-400 hover:text-accent-300 underline transition-colors"
              >
                Load sample phishing email
              </button>
            </div>
          )}

          {/* File upload method */}
          {uploadMethod === 'file' && (
            <div className="space-y-3">
              <label className="text-xs text-text-secondary uppercase tracking-wider">
                Upload .eml File
              </label>
              
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-border rounded-lg p-8 
                           text-center cursor-pointer hover:border-accent-500 hover:bg-bg-raised/50 
                           transition-all duration-150"
              >
                <Upload size={32} className="mx-auto text-text-secondary mb-2" />
                <p className="text-sm text-text-primary">
                  Click to select or drag & drop .eml file
                </p>
                <p className="text-xs text-text-muted mt-1">
                  Supports exported emails from Gmail, Outlook, Thunderbird
                </p>
              </div>
              
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml"
                onChange={handleFileSelect}
                className="hidden"
              />
              
              {selectedFile && (
                <div className="bg-bg-raised border border-border rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <FileText size={16} className="text-accent-400" />
                    <span className="text-sm text-text-primary">{selectedFile.name}</span>
                    <span className="text-xs text-text-muted ml-auto">
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Forward email instructions */}
          <div className="mt-4 pt-4 border-t border-border">
            <div className="flex items-center gap-2 mb-2">
              <Forward size={14} className="text-accent-400" />
              <span className="text-xs font-semibold text-accent-400 uppercase tracking-wider">
                Forward to Analyze
              </span>
            </div>
            
            <p className="text-xs text-text-secondary mb-2">
              Simply forward suspicious emails to:
            </p>
            
            <div className="flex items-center gap-2">
              <code className="bg-bg-raised border border-border px-3 py-2 rounded text-sm text-text-primary font-mono">
                {forwardEmail}
              </code>
              <Button
                onClick={copyForwardAddress}
                variant="secondary"
                size="sm"
              >
                Copy
              </Button>
            </div>
            
            <p className="text-xs text-text-muted mt-2">
              We'll analyze and send results back to your inbox within seconds.
            </p>
          </div>
        </div>
      )}

      {/* Submit button */}
      <Button
        onClick={handleSubmit}
        disabled={!canSubmit() || loading}
        loading={loading}
        className="w-full"
      >
        Analyze {tab === 'url' ? 'URL' : 'Email'}
      </Button>
    </Card>
  )
}