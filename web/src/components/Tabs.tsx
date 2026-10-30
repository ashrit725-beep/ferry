/**
 * Tabs following the WAI-ARIA tabs pattern: one tab stop for the list, arrow
 * keys (and Home/End) move between tabs and select them. Every panel stays
 * mounted and inactive ones are hidden, so work in progress in one tab (an
 * unsaved policy draft, say) survives a visit to another.
 */

import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';

export interface TabItem<T extends string> {
  id: T;
  label: string;
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
  const baseId = useId();
  const refs = useRef(new Map<T, HTMLButtonElement>());

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number): void => {
    let next: number | null = null;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    if (next === null) return;
    event.preventDefault();
    const tab = tabs[next];
    if (!tab) return;
    refs.current.get(tab.id)?.focus();
    onSelect(tab.id);
  };

  return (
    <div className="tabs">
      <div role="tablist" aria-label={label} className="tabs__list">
        {tabs.map((tab, i) => (
          <button
            key={tab.id}
            ref={(el) => {
              if (el) refs.current.set(tab.id, el);
              else refs.current.delete(tab.id);
            }}
            type="button"
            role="tab"
            id={`${baseId}-tab-${tab.id}`}
            aria-selected={tab.id === selected}
            aria-controls={`${baseId}-panel-${tab.id}`}
            tabIndex={tab.id === selected ? 0 : -1}
            className="tabs__tab"
            onClick={() => onSelect(tab.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`${baseId}-panel-${tab.id}`}
          aria-labelledby={`${baseId}-tab-${tab.id}`}
          className="tabs__panel"
          hidden={tab.id !== selected}
        >
          {panels[tab.id]}
        </div>
      ))}
    </div>
  );
}
