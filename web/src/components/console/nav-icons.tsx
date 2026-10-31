/** Lucide icons for the six console pages, shared by the rail and the palette. */

import { FileCheck2, KeyRound, LayoutGrid, Package, ScrollText, Server, type LucideIcon } from 'lucide-react';
import type { SVGProps } from 'react';
import type { NavPage } from '../../router.ts';

export const NAV_ICONS: Record<NavPage, LucideIcon> = {
  overview: LayoutGrid,
  bundles: Package,
  models: Server,
  access: KeyRound,
  audit: ScrollText,
  evidence: FileCheck2,
};

type LogoProps = Omit<SVGProps<SVGSVGElement>, 'children' | 'ref'>;

/** The Ferry mark, drawn inline on a 16 px grid (a brand asset). Decorative. */
export function IconLogo(props: LogoProps) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d="M1.75 10.25h12.5l-1.9 3.5H3.65z" />
      <path d="M8 1.75v8.5" />
      <path d="M8 2.75l4.5 5.75H8" />
    </svg>
  );
}
