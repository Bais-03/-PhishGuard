import React from 'react'
import { Loader2 } from 'lucide-react'
import clsx from 'clsx'

const Button = ({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled = false,
  className = '',
  onClick,
  type = 'button',
  ...props
}) => {
  const baseStyles = 'inline-flex items-center justify-center font-medium rounded-button transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-bg-base disabled:opacity-40 disabled:cursor-not-allowed'
  
  const variants = {
    primary: 'bg-accent-500 hover:bg-accent-400 active:bg-accent-600 text-white shadow-glow-accent/30 focus:ring-accent-500',
    secondary: 'bg-bg-raised hover:bg-border border border-border-strong text-text-primary focus:ring-border-strong',
    danger: 'bg-danger-500 hover:bg-danger-600 text-white shadow-glow-danger/20 focus:ring-danger-500',
    ghost: 'bg-transparent text-text-secondary hover:text-text-primary hover:bg-bg-raised focus:ring-accent-500',
  }
  
  const sizes = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-5 py-2.5 text-base',
    lg: 'px-7 py-3.5 text-lg',
  }
  
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={clsx(
        baseStyles,
        variants[variant],
        sizes[size],
        className
      )}
      {...props}
    >
      {loading && <Loader2 size={16} className="mr-2 animate-spin" />}
      {children}
    </button>
  )
}

export default Button