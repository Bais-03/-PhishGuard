import React, { useState, useCallback } from 'react'
import Navbar from './components/Navbar'
import HomePage from './pages/HomePage'
import AnalysisPage from './pages/AnalysisPage'
import InsightsPage from './pages/InsightsPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import { analyzeUrl, analyzeEmail, analyzeEmailFile } from './api/client'

const MAX_HISTORY = 10

export default function App() {
  const [activePage, setActivePage] = useState('home')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])

  const handleAnalyze = useCallback(async ({ type, value }) => {
    setLoading(true)
    setError(null)
    try {
      let data
      if (type === 'url') data = await analyzeUrl(value)
      else if (type === 'email') data = await analyzeEmail(value)
      else if (type === 'email_file') data = await analyzeEmailFile(value)
      else throw new Error(`Unknown type: ${type}`)
      
      setResult(data)
      setHistory(prev => [
        { input: typeof value === 'string' ? value.slice(0, 60) : value.name, result: data },
        ...prev.slice(0, MAX_HISTORY - 1),
      ])
      setActivePage('insights')
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Analysis failed'
      setError(msg)
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleHistorySelect = useCallback((item) => {
    setResult(item.result)
    setError(null)
    setActivePage('insights')
  }, [])

  const renderPage = () => {
    switch (activePage) {
      case 'home':
        return <HomePage onNavigate={setActivePage} />
      case 'analysis':
        return <AnalysisPage onAnalyze={handleAnalyze} loading={loading} onNavigate={setActivePage} />
      case 'insights':
        return <InsightsPage 
          result={result} 
          loading={loading} 
          error={error} 
          history={history} 
          onAnalyze={handleAnalyze}
          onHistorySelect={handleHistorySelect} 
          onNavigate={setActivePage} 
        />
      case 'reports':
        return <ReportsPage history={history} onSelect={handleHistorySelect} />
      case 'settings':
        return <SettingsPage />
      default:
        return <HomePage onNavigate={setActivePage} />
    }
  }

  return (
    <div className="min-h-screen bg-bg-base">
      <div className="cyber-grid" />
      <Navbar activePage={activePage} onNavigate={setActivePage} />
      <main className="relative z-10 pt-14">{renderPage()}</main>
    </div>
  )
}