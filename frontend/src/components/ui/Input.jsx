import React from 'react'
import clsx from 'clsx'

const Input = React.forwardRef(({
  label,
  error,
  type = 'text',
  className = '',
  inputClassName = '',
  ...props
}, ref) => {
  return (
    <div className={clsx('w-full', className)}>
      {label && (
        <label className="block text-xs font-medium text-text-secondary uppercase tracking-widest mb-1.5">
          {label}
        </label>
      )}
      <input
        ref={ref}
        type={type}
        className={clsx(
          'w-full px-3.5 py-2.5 bg-bg-raised border border-border rounded-button text-text-primary placeholder-text-muted font-mono text-sm',
          'focus:outline-none focus:ring-1 focus:ring-accent-500 focus:border-accent-500',
          'transition-all duration-150',
          error ? 'border-danger-500' : 'border-border',
          inputClassName
        )}
        {...props}
      />
      {error && (
        <p className="mt-1 text-xs text-danger-400">{error}</p>
      )}
    </div>
  )
})

Input.displayName = 'Input'

export default Input