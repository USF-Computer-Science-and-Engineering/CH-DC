
import { X, AlertCircle } from 'lucide-react';
import { cn } from '../lib/utils';

export interface ToastMessage {
    id: string;
    title: string;
    description?: string;
    type?: 'info' | 'warning' | 'error' | 'success';
}

interface ToastProps {
    toasts: ToastMessage[];
    onDismiss: (id: string) => void;
}

export function Toaster({ toasts, onDismiss }: ToastProps) {
    if (toasts.length === 0) return null;

    return (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
            {toasts.map(toast => (
                <div
                    key={toast.id}
                    className={cn(
                        "pointer-events-auto bg-card border shadow-lg rounded-lg p-4 flex items-start gap-3 animate-in slide-in-from-right-full duration-300",
                        toast.type === 'warning' ? "border-yellow-500/50 bg-yellow-500/10" : "border-border"
                    )}
                >
                    <div className={cn(
                        "mt-0.5",
                        toast.type === 'warning' ? "text-yellow-500" : "text-primary"
                    )}>
                        <AlertCircle className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                        <h4 className="font-semibold text-sm">{toast.title}</h4>
                        {toast.description && (
                            <p className="text-xs text-muted-foreground mt-1">{toast.description}</p>
                        )}
                    </div>
                    <button
                        onClick={() => onDismiss(toast.id)}
                        className="text-muted-foreground hover:text-foreground transition-colors"
                    >
                        <X className="w-4 h-4" />
                    </button>
                </div>
            ))}
        </div>
    );
}
