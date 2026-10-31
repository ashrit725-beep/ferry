/**
 * IconButton: an icon-only control with a required accessible name, a tooltip
 * carrying that name, a 32 px (or 28 px) drawn size and a 40 px hit area (44 px under a coarse pointer).
 */

import type { ComponentProps, ReactNode } from 'react';
import { Button } from '../ui/button.tsx';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip.tsx';
import { cn } from '@/lib/utils';

export interface IconButtonProps extends Omit<ComponentProps<typeof Button>, 'children' | 'size'> {
  /** The accessible name and the tooltip text. */
  label: string;
  children: ReactNode;
  /** Extra tooltip content (a keyboard hint). */
  hint?: ReactNode;
  size?: 'default' | 'sm';
  /** Skip the tooltip (the control sits beside its own visible text). */
  noTooltip?: boolean;
}

export function IconButton({ label, children, hint, size = 'default', noTooltip = false, className, variant = 'ghost', ...props }: IconButtonProps) {
  const button = (
    <Button
      type="button"
      variant={variant}
      size={size === 'sm' ? 'icon-sm' : 'icon'}
      aria-label={label}
      className={cn(
        'relative after:absolute after:content-[""]',
        size === 'sm' ? 'after:-inset-1.5 pointer-coarse:after:-inset-2' : 'after:-inset-1 pointer-coarse:after:-inset-1.5',
        className,
      )}
      {...props}
    >
      {children}
    </Button>
  );
  if (noTooltip) return button;
  return (
    <Tooltip>
      <TooltipTrigger render={button} />
      <TooltipContent>
        {label}
        {hint}
      </TooltipContent>
    </Tooltip>
  );
}
