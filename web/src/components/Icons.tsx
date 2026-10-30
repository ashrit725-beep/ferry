/**
 * The console's few icons, drawn inline on a 16 px grid. They are decorative:
 * every icon sits next to visible text or inside a control with its own
 * accessible name, so all of them are hidden from assistive technology.
 */

import type { ReactNode, SVGProps } from 'react';

type IconProps = Omit<SVGProps<SVGSVGElement>, 'children'>;

function Svg({ children, ...props }: IconProps & { children: ReactNode }) {
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
      {children}
    </svg>
  );
}

export function IconLogo(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M1.75 10.25h12.5l-1.9 3.5H3.65z" />
      <path d="M8 1.75v8.5" />
      <path d="M8 2.75l4.5 5.75H8" />
    </Svg>
  );
}

export function IconOverview(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="2" y="2" width="5" height="5" rx="1" />
      <rect x="9" y="2" width="5" height="5" rx="1" />
      <rect x="2" y="9" width="5" height="5" rx="1" />
      <rect x="9" y="9" width="5" height="5" rx="1" />
    </Svg>
  );
}

export function IconBundles(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 1.75 13.75 5v6L8 14.25 2.25 11V5z" />
      <path d="M2.25 5 8 8.25 13.75 5M8 8.25v6" />
    </Svg>
  );
}

export function IconModels(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="4" y="4" width="8" height="8" rx="1" />
      <path d="M6.5 1.75V4M9.5 1.75V4M6.5 12v2.25M9.5 12v2.25M1.75 6.5H4M1.75 9.5H4M12 6.5h2.25M12 9.5h2.25" />
    </Svg>
  );
}

export function IconAccess(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="5.25" cy="10.75" r="3" />
      <path d="m7.4 8.6 6.35-6.35M11.25 4.75l1.75 1.75M9.5 6.5l1.25 1.25" />
    </Svg>
  );
}

export function IconAudit(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M5.75 4h8M5.75 8h8M5.75 12h8" />
      <circle cx="2.75" cy="4" r="0.9" fill="currentColor" stroke="none" />
      <circle cx="2.75" cy="8" r="0.9" fill="currentColor" stroke="none" />
      <circle cx="2.75" cy="12" r="0.9" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export function IconEvidence(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M9.5 1.75H4.25a1 1 0 0 0-1 1v10.5a1 1 0 0 0 1 1h7.5a1 1 0 0 0 1-1V4.75z" />
      <path d="M9.5 1.75v3h3" />
      <path d="m5.75 9.25 1.5 1.5 3-3" />
    </Svg>
  );
}

export function IconCopy(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25" />
      <path d="M10.75 5.25v-2a1 1 0 0 0-1-1h-6.5a1 1 0 0 0-1 1v6.5a1 1 0 0 0 1 1h2" />
    </Svg>
  );
}

export function IconCheck(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="m3 8.5 3.25 3.25L13 5" />
    </Svg>
  );
}

export function IconCross(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M4 4l8 8M12 4l-8 8" />
    </Svg>
  );
}

export function IconExclaim(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 3v6" />
      <path d="M8 12.5v.25" />
    </Svg>
  );
}

export function IconDot(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="8" cy="8" r="3" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export function IconAlert(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 2.25 14.25 13.5H1.75z" />
      <path d="M8 6.5v3" />
      <path d="M8 11.5v.25" />
    </Svg>
  );
}

export function IconInfo(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="8" cy="8" r="6.25" />
      <path d="M8 7.25v4" />
      <path d="M8 4.75v.25" />
    </Svg>
  );
}

export function IconDownload(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 2v8.5M4.5 7 8 10.5 11.5 7" />
      <path d="M2.5 13.5h11" />
    </Svg>
  );
}

export function IconRefresh(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M13.25 8a5.25 5.25 0 1 1-1.54-3.71" />
      <path d="M13.25 2.5v3h-3" />
    </Svg>
  );
}

export function IconSignOut(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M6 2.75H3.75a1 1 0 0 0-1 1v8.5a1 1 0 0 0 1 1H6" />
      <path d="M10.5 11 13.5 8l-3-3M13.5 8H6" />
    </Svg>
  );
}

export function IconPlus(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 3v10M3 8h10" />
    </Svg>
  );
}

export function IconShield(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 1.75 13.25 3.5v4.25c0 3.1-2.2 5.4-5.25 6.5-3.05-1.1-5.25-3.4-5.25-6.5V3.5z" />
      <path d="m5.75 8 1.5 1.5 3-3" />
    </Svg>
  );
}
