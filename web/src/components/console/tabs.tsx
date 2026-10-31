/**
 * Tabs on the Base UI tabs (WAI-ARIA tabs pattern: arrow keys move and
 * select, one tab stop). Every panel stays mounted and inactive ones are
 * hidden, so work in progress in one tab survives a visit to another.
 */

import type { ReactNode } from 'react';
import { Tabs as TabsRoot, TabsContent, TabsList, TabsTrigger } from '../ui/tabs.tsx';

export interface TabItem<T extends string> {
  id: T;
  label: string;
  count?: number;
}

export function Tabs<T extends string>({
  tabs,
  selected,
  onSelect,
  label,
  panels,
}: {
  tabs: readonly TabItem<T>[];
  selected: T;
  onSelect: (id: T) => void;
  label: string;
  panels: Record<T, ReactNode>;
}) {
  return (
    <TabsRoot
      value={selected}
      onValueChange={(value) => {
        const tab = tabs.find((t) => t.id === value);
        if (tab) onSelect(tab.id);
      }}
      className="gap-3"
    >
      <TabsList variant="line" activateOnFocus aria-label={label} className="h-9 w-full justify-start gap-4 rounded-none border-b border-hairline p-0">
        {tabs.map((tab) => (
          <TabsTrigger
            key={tab.id}
            value={tab.id}
            className="h-9 flex-none rounded-none border-0 px-1 text-sm text-text-2 hover:text-bone data-active:text-bone after:bottom-[-1px] after:h-0.5 after:bg-amber"
          >
            {tab.label}
            {tab.count !== undefined ? <span className="font-mono text-xs text-text-3 tabular-nums">{tab.count}</span> : null}
          </TabsTrigger>
        ))}
      </TabsList>
      {tabs.map((tab) => (
        <TabsContent key={tab.id} value={tab.id} keepMounted>
          {panels[tab.id]}
        </TabsContent>
      ))}
    </TabsRoot>
  );
}
