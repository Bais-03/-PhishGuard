import React from 'react'
import clsx from 'clsx'

const Badge = ({ children, variant = 'neutral', className = '', ...props }) => {
  const variants = {
    safe: 'bg-success-100 text-success-800',
    warning: 'bg-secondary-100 text-secondary-800',
    danger: 'bg-danger-100 text-danger-800',
    neutral: 'bg-neutral-100 text-neutral-700',
    critical: 'bg-danger-100 text-danger-800',
    high: 'bg-danger-50 text-danger-700',
    medium: 'bg-secondary-100 text-secondary-800',
    low: 'bg-neutral-100 text-neutral-600',
  }
  
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2.5 py-0.5 rounded-badge text-xs font-medium',
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </span>
  )
}

// Severity badge for flags
export const SeverityBadge = ({ severity, score, ...props }) => {
  const severityMap = {
    CRITICAL: { variant: 'critical', label: 'CRITICAL' },
    HIGH: { variant: 'high', label: 'HIGH' },
    MEDIUM: { variant: 'medium', label: 'MEDIUM' },
    LOW: { variant: 'low', label: 'LOW' },
    NONE: { variant: 'neutral', label: 'NONE' },
  }
  
  const config = severityMap[severity] || severityMap.LOW
  
  return (
    <Badge variant={config.variant} {...props}>
      {config.label}
      {score !== undefined && ` +${score}pts`}
    </Badge>
  )
}

export default Badge