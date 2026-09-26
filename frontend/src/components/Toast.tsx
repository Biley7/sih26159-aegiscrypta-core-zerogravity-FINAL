import React from 'react';
import { AlertCircle, X, RefreshCw, Radio } from 'lucide-react';

interface ToastProps {
  message: string;
  type?: 'amber' | 'rose' | 'emerald' | 'cyan';
  onDismiss: () => void;
  onRetry?: () => void;
  isRetrying?: boolean;
}

export const Toast: React.FC<ToastProps> = ({
  message,
  type = 'amber',
  onDismiss,
  onRetry,
  isRetrying = false
}) => {
  return (
    <div className={`soc-toast-banner ${type}`} role="alert">
      <div className="toast-left">
        <Radio size={14} className="toast-pulse-icon" />
        <span className="toast-message font-mono text-xs">{message}</span>
      </div>

      <div className="toast-actions">
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            disabled={isRetrying}
            className="toast-retry-btn font-mono text-xs flex items-center gap-1"
            title="Probe backend health"
          >
            <RefreshCw size={11} className={isRetrying ? 'spinning' : ''} />
            <span>{isRetrying ? 'Checking...' : 'Probe Live'}</span>
          </button>
        )}

        <button
          type="button"
          onClick={onDismiss}
          className="toast-close-btn"
          title="Dismiss notification"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
};
