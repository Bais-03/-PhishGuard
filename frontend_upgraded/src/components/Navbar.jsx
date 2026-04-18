import React, { useState } from 'react'
import { Shield, Home, Search, LayoutDashboard, FileText, Settings, User, Menu, X, Zap } from 'lucide-react'
import clsx from 'clsx'

const NAV_ITEMS = [
  { id: 'home',       label: 'Home',       icon: Home },
  { id: 'analysis',   label: 'Analysis',   icon: Search },
  { id: 'insights',   label: 'Insights',   icon: LayoutDashboard },
  { id: 'reports',    label: 'Reports',    icon: FileText },
  { id: 'settings',   label: 'Settings',   icon: Settings },
]

export default function Navbar({ activePage, onNavigate }) {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <nav className="fixed top-0 inset-x-0 z-50 border-b border-border bg-bg-base/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center gap-6">
        
        {/* Logo */}
        <button
          onClick={() => { onNavigate('home'); setMobileOpen(false) }}
          className="flex items-center gap-2.5 shrink-0 group"
        >
          <div className="w-8 h-8 bg-accent-500 rounded-lg flex items-center justify-center shadow-glow-accent group-hover:bg-accent-400 transition-colors">
            <Shield size={16} className="text-white" />
          </div>
          <span className="text-sm font-semibold text-text-primary tracking-tight">PhishGuard</span>
        </button>

        {/* Desktop Navigation */}
        <div className="hidden md:flex items-center gap-1 flex-1">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={clsx(
                'flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all duration-150',
                activePage === id
                  ? 'bg-accent-500/10 text-accent-400 border border-accent-500/20'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-raised'
              )}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-2">
          {/* 11-Layer Badge */}
          <span className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-accent-400 border border-accent-500/30 bg-accent-500/5 rounded px-2.5 py-1">
            <Zap size={10} />
            11-Layer
          </span>
          
          {/* User Avatar */}
          <button className="w-8 h-8 rounded-full bg-bg-raised border border-border flex items-center justify-center hover:border-border-strong transition-colors">
            <User size={14} className="text-text-secondary" />
          </button>
          
          {/* Mobile Menu Button */}
          <button
            className="md:hidden w-8 h-8 flex items-center justify-center text-text-secondary hover:text-text-primary"
            onClick={() => setMobileOpen(v => !v)}
          >
            {mobileOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileOpen && (
        <div className="md:hidden border-t border-border bg-bg-surface/95 backdrop-blur-md">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => { onNavigate(id); setMobileOpen(false) }}
              className={clsx(
                'w-full flex items-center gap-3 px-5 py-3 text-sm font-medium transition-colors',
                activePage === id
                  ? 'text-accent-400 bg-accent-500/5 border-l-2 border-accent-500'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-raised border-l-2 border-transparent'
              )}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </div>
      )}
    </nav>
  )
}