import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { cn } from '../lib/utils';

interface Props {
    text: string | number;
    label?: string; // Optional label to show
    className?: string;
    truncate?: boolean;
}

export function Copyable({ text, label, className, truncate = false }: Props) {
    const [copied, setCopied] = useState(false);
    const value = String(text);

    const handleCopy = async (e: React.MouseEvent) => {
        e.stopPropagation();
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy', err);
        }
    };

    return (
        <div
            className={cn("group flex items-center gap-1.5 cursor-pointer hover:text-foreground transition-colors", className)}
            onClick={handleCopy}
            title={`Copy ${value}`}
        >
            <span className={cn(truncate && "truncate")}>
                {label || value}
            </span>
            <span className="opacity-0 group-hover:opacity-100 transition-opacity">
                {copied ? (
                    <Check className="w-3 h-3 text-green-500" />
                ) : (
                    <Copy className="w-3 h-3 text-muted-foreground" />
                )}
            </span>
        </div>
    );
}
