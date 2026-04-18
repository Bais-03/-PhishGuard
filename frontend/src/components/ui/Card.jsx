import React from 'react'
import clsx from 'clsx'

const Card = ({ children, className = '', hover = true, variant = 'default', ...props }) => {
  const variants = {
    default: 'bg-bg-surface border-border',
    elevated: 'bg-bg-raised border-border-strong shadow-card',
    ghost: 'bg-transparent border-border',
  }

  return (
    <div
      className={clsx(
        'rounded-card border p-6 transition-all duration-200',
        variants[variant],
        hover && 'hover:shadow-card-hover hover:border-border-strong',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}

const CardHeader = ({ children, className = '' }) => (
  <div className={clsx('mb-4 pb-3 border-b border-border', className)}>
    {children}
  </div>
)

const CardTitle = ({ children, className = '' }) => (
  <h3 className={clsx('text-base font-semibold text-text-primary', className)}>
    {children}
  </h3>
)

const CardDescription = ({ children, className = '' }) => (
  <p className={clsx('text-sm text-text-muted', className)}>
    {children}
  </p>
)

const CardContent = ({ children, className = '' }) => (
  <div className={clsx('', className)}>
    {children}
  </div>
)

const CardFooter = ({ children, className = '' }) => (
  <div className={clsx('mt-4 pt-3 border-t border-border', className)}>
    {children}
  </div>
)

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter }
export default Card