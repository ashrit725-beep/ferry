/**
 * DataTable: a dense table (12 px, 32 px rows) with a sticky header, optional
 * sort, loading skeleton, empty and error states, row tone that holds its
 * alert colour until acknowledged, and in-place rerank by row identity
 * (motion layout, opt in with `rerank`, at most about 50 rows).
 */

import { useEffect, useRef, useState, type KeyboardEventHandler, type MouseEventHandler, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { motion, useReducedMotionConfig } from 'motion/react';
import type { Tone } from '../../status.ts';
import { EmptyState, ErrorState, TableSkeleton } from './states.tsx';
import { cn } from '@/lib/utils';

export interface Column<Row> {
  id: string;
  header: ReactNode;
  cell: (row: Row) => ReactNode;
  align?: 'left' | 'right';
  /** Width utility class for the header cell ("w-32"). */
  width?: string;
  /** Values set in Azeret Mono. */
  mono?: boolean;
  nowrap?: boolean;
  /** Sortable when given. */
  sortValue?: (row: Row) => string | number | null;
  /** Visually hidden header (an actions column). */
  srOnlyHeader?: boolean;
  /** The label of this value when rows stack on phones (defaults to a string header). */
  label?: string;
  /** Leave this value out of the stacked phone layout (the row's detail view carries it). */
  hideOnPhone?: boolean;
  className?: string;
}

/** Attributes a page may put on a row (selection, keyboard navigation). */
export interface RowAttrs {
  id?: string;
  className?: string;
  tabIndex?: number;
  title?: string;
  onClick?: MouseEventHandler<HTMLTableRowElement>;
  onKeyDown?: KeyboardEventHandler<HTMLTableRowElement>;
  'aria-selected'?: boolean;
  'aria-current'?: 'true' | 'page';
}

export type SortDir = 'asc' | 'desc';
export interface SortState {
  column: string;
  dir: SortDir;
}

export interface DataTableProps<Row> {
  columns: ReadonlyArray<Column<Row>>;
  rows: ReadonlyArray<Row> | null;
  rowKey: (row: Row) => string;
  caption: string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** Empty state content; a string becomes the title. */
  empty?: ReactNode;
  emptyTitle?: string;
  /** Tone of a row (bad and warn tint it; the tint holds while `held` says so). */
  rowTone?: (row: Row) => Tone | null;
  /** True while a row's alert has not been acknowledged. */
  held?: (row: Row) => boolean;
  selectedKey?: string | null;
  rowProps?: (row: Row) => RowAttrs;
  /** Animate rows into their new position when the order changes. */
  rerank?: boolean;
  sort?: SortState | null;
  defaultSort?: SortState | null;
  onSortChange?: (sort: SortState | null) => void;
  /** Scroll inside the table container at this height class ("max-h-[70vh]"). */
  maxHeight?: string;
  /** Override the width floor ("min-w-0" lets a narrow side panel fit the table). */
  minWidth?: string;
  skeletonRows?: number;
  /**
   * Below 768 px, render each row as stacked label/value lines (first column as
   * the row title, actions on their own line) instead of a sideways-scrolling
   * table. Defaults to on for tables with four or more columns or row actions.
   */
  stack?: boolean;
  className?: string;
}

function compare(a: string | number | null, b: string | number | null): number {
  if (a === null) return b === null ? 0 : 1;
  if (b === null) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), 'en', { numeric: true, sensitivity: 'base' });
}

/**
 * A floor under the table's width (about 7rem a column) so narrow viewports
 * scroll sideways, with an edge cue, instead of squeezing cells to a few
 * characters.
 */
const MIN_WIDTH = ['', '', '', 'min-w-[21rem]', 'min-w-[28rem]', 'min-w-[35rem]', 'min-w-[42rem]', 'min-w-[49rem]', 'min-w-[56rem]'];

const ROW_TONE: Partial<Record<Tone, string>> = {
  bad: 'bg-bad-subtle/70',
  warn: 'bg-amber-subtle/70',
  info: 'bg-info-subtle/50',
};

export function DataTable<Row>({
  columns,
  rows,
  rowKey,
  caption,
  loading = false,
  error = null,
  onRetry,
  empty,
  emptyTitle = 'Nothing to show.',
  rowTone,
  held,
  selectedKey = null,
  rowProps,
  rerank = false,
  sort,
  defaultSort = null,
  onSortChange,
  maxHeight = 'max-h-[70vh]',
  minWidth,
  skeletonRows = 5,
  stack,
  className,
}: DataTableProps<Row>) {
  const reduce = useReducedMotionConfig();
  const scroller = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState<{ overflow: boolean; moreRight: boolean }>({ overflow: false, moreRight: false });
  const [innerSort, setInnerSort] = useState<SortState | null>(defaultSort);
  const current = sort === undefined ? innerSort : sort;

  const setSort = (next: SortState | null): void => {
    if (sort === undefined) setInnerSort(next);
    onSortChange?.(next);
  };

  const toggle = (column: Column<Row>): void => {
    if (!column.sortValue) return;
    if (current?.column !== column.id) setSort({ column: column.id, dir: 'asc' });
    else if (current.dir === 'asc') setSort({ column: column.id, dir: 'desc' });
    else setSort(null);
  };

  // A visible edge when columns run past the panel: the table scrolls sideways.
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const update = (): void => {
      const overflow = el.scrollWidth > el.clientWidth + 1;
      const moreRight = overflow && el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
      setScroll((prev) => (prev.overflow === overflow && prev.moreRight === moreRight ? prev : { overflow, moreRight }));
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    const table = el.firstElementChild;
    if (table) observer.observe(table);
    el.addEventListener('scroll', update, { passive: true });
    // A focus stop under the pinned actions column is scrolled out from beneath
    // it (WCAG 2.4.11): the browser sees it as in view, so it would not move.
    const reveal = (event: FocusEvent): void => {
      const target = event.target;
      if (!(target instanceof HTMLElement) || target.closest('[data-pin]')) return;
      const pin = target.closest('tr')?.querySelector<HTMLElement>(':scope > [data-pin]');
      if (!pin || getComputedStyle(pin).position !== 'sticky') return;
      const t = target.getBoundingClientRect();
      const p = pin.getBoundingClientRect();
      if (t.right > p.left && t.left < p.right) el.scrollLeft += t.right - p.left + 8;
    };
    el.addEventListener('focusin', reveal);
    return () => {
      observer.disconnect();
      el.removeEventListener('scroll', update);
      el.removeEventListener('focusin', reveal);
    };
  });

  if (rows === null) {
    if (error) return <ErrorState error={error} onRetry={onRetry} />;
    if (loading) return <TableSkeleton rows={skeletonRows} columns={Math.min(columns.length, 5)} />;
  }

  const sortColumn = current ? columns.find((c) => c.id === current.column) : undefined;
  const sorted =
    rows && sortColumn?.sortValue
      ? rows.toSorted((a, b) => {
          const value = sortColumn.sortValue;
          if (!value) return 0;
          const r = compare(value(a), value(b));
          return current?.dir === 'desc' ? -r : r;
        })
      : (rows ?? []);

  const RowTag = rerank && !reduce ? motion.tr : 'tr';
  const pinned = columns.some((c) => c.id === 'actions');
  const stacked = stack ?? (columns.length >= 4 || pinned);
  // Row actions stay in view at every width: the actions column is pinned to the
  // right edge, opaque (it follows the row's hover, selection and tone), with a
  // hairline edge only while the other columns scroll beneath it.
  const PIN = cn(
    'md:sticky md:right-0 md:z-[1] group-data-[overflow]/dt:md:bg-panel',
    'group-data-[overflow]/dt:md:shadow-[inset_1px_0_0_0_var(--hairline),-8px_0_8px_-8px_var(--ground)]',
  );
  const PIN_ROW = cn(
    '[tr:hover>&]:md:bg-hover [tr[data-selected]>&]:md:bg-hover',
    '[tr[data-tone=bad]>&]:md:bg-[color-mix(in_srgb,var(--bad-subtle)_70%,var(--panel))]',
    '[tr[data-tone=warn]>&]:md:bg-[color-mix(in_srgb,var(--amber-subtle)_70%,var(--panel))]',
    '[tr[data-tone=info]>&]:md:bg-[color-mix(in_srgb,var(--info-subtle)_50%,var(--panel))]',
  );
  const labelOf = (column: Column<Row>): string | undefined => column.label ?? (typeof column.header === 'string' ? column.header : undefined);

  if (sorted.length === 0) {
    // Outside any scrolling table, so the sentence is never cut by a wide column set.
    return (
      <div className={cn('w-full', className)}>
        <p className="sr-only">{caption}</p>
        {typeof empty === 'string' || empty === undefined ? <EmptyState title={typeof empty === 'string' ? empty : emptyTitle} /> : empty}
      </div>
    );
  }

  return (
    <div className={cn('group/dt relative w-full', className)} data-overflow={scroll.overflow || undefined} data-stacked={stacked || undefined}>
    {/* pb-1 keeps the 40 px hit area of a 24 px row button (4 px past the last row) inside the scroller, so no scrollbar appears beside a short table.
        Stacked on phones, the rows are part of the page: no height cap and no inner scroller to hide rows in. */}
    <div ref={scroller} className={cn('w-full overflow-auto pb-1 [scrollbar-gutter:stable]', maxHeight, stacked && 'max-md:max-h-none max-md:overflow-visible')}>
      <table
        className={cn(
          'w-full border-collapse text-xs',
          minWidth ?? MIN_WIDTH[Math.min(columns.length, MIN_WIDTH.length - 1)],
          stacked && 'max-md:block max-md:min-w-0',
        )}
      >
        <caption className="sr-only">{caption}</caption>
        <thead className={cn('sticky top-0 z-10 bg-panel', stacked && 'max-md:hidden')}>
          <tr className="border-b border-hairline">
            {columns.map((column) => {
              const sortable = Boolean(column.sortValue);
              const active = current?.column === column.id;
              const ariaSort = active ? (current?.dir === 'asc' ? 'ascending' : 'descending') : sortable ? 'none' : undefined;
              const Icon = active ? (current?.dir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
              return (
                <th
                  key={column.id}
                  scope="col"
                  aria-sort={ariaSort}
                  data-pin={column.id === 'actions' || undefined}
                  className={cn('h-8 px-3 text-left align-middle text-xs font-medium whitespace-nowrap text-text-2', column.align === 'right' && 'text-right', column.id === 'actions' && PIN, column.width)}
                >
                  {column.srOnlyHeader ? (
                    <span className="sr-only">{column.header}</span>
                  ) : sortable ? (
                    <button
                      type="button"
                      onClick={() => toggle(column)}
                      className={cn('-mx-1 inline-flex h-6 items-center gap-1 rounded-sm px-1 hover:bg-hover hover:text-bone', active && 'text-bone')}
                    >
                      {column.header}
                      <Icon aria-hidden="true" className={cn('size-3', !active && 'opacity-50')} />
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className={cn(stacked && 'max-md:block')}>
          {sorted.map((row) => {
              const key = rowKey(row);
              const tone = rowTone?.(row) ?? null;
              const holding = held ? held(row) : true;
              const tint = tone && holding ? ROW_TONE[tone] : undefined;
              const selected = selectedKey !== null && selectedKey === key;
              const { className: extraClass, ...extra } = rowProps?.(row) ?? {};
              const classes = cn(
                'h-8 border-b border-hairline last:border-0 hover:bg-hover',
                stacked && 'max-md:flex max-md:h-auto max-md:flex-col max-md:gap-1 max-md:py-2.5',
                tint,
                selected && 'bg-hover shadow-[inset_1px_0_0_0_var(--amber)]',
                extraClass,
              );
              const cells = columns.map((column, index) => {
                const label = index > 0 && column.id !== 'actions' ? labelOf(column) : undefined;
                return (
                  <td
                    key={column.id}
                    data-label={stacked ? label : undefined}
                    data-pin={column.id === 'actions' || undefined}
                    className={cn(
                      'px-3 py-1 align-middle text-bone',
                      column.align === 'right' && 'text-right tabular-nums',
                      column.mono && 'font-mono',
                      // Words and identifiers never break mid-segment: they wrap at hyphens and
                      // spaces only, and a column too narrow for one makes the table scroll.
                      column.nowrap ? 'whitespace-nowrap' : 'break-words',
                      column.id === 'actions' && [PIN, PIN_ROW],
                      // In-table stamps are compact: glyph and sentence-case word, no box.
                      '[&_[data-stamp]]:h-auto [&_[data-stamp]]:border-transparent [&_[data-stamp]]:bg-transparent [&_[data-stamp]]:px-0 [&_[data-stamp]]:text-xs [&_[data-stamp]]:tracking-normal [&_[data-stamp]]:normal-case',
                      '[&_[data-stamp-word]]:inline-block [&_[data-stamp-word]]:first-letter:uppercase',
                      column.className,
                      // Phones: one line per value, its column name in front; the first
                      // column is the row's title and the actions get a line of their own.
                      stacked && [
                        'max-md:grid max-md:w-auto max-md:max-w-none max-md:min-w-0 max-md:grid-cols-[6.5rem_minmax(0,1fr)] max-md:gap-x-3 max-md:py-0 max-md:text-left max-md:whitespace-normal',
                        label
                          ? 'max-md:before:pt-px max-md:before:font-sans max-md:before:text-2xs max-md:before:text-text-3 max-md:before:content-[attr(data-label)]'
                          : 'max-md:grid-cols-[minmax(0,1fr)]',
                        index === 0 && 'max-md:text-sm max-md:font-medium',
                        column.id === 'actions' && 'max-md:pt-1.5 max-md:[&>div>div]:justify-start max-md:[&>div>div]:flex-wrap',
                        // A value the row does not have (an app's expiry, a revoked key's actions) takes no line.
                        'max-md:has-[>div:empty]:hidden',
                        column.hideOnPhone && 'max-md:hidden',
                      ],
                    )}
                  >
                    {stacked ? <div className="contents max-md:block max-md:min-w-0">{column.cell(row)}</div> : column.cell(row)}
                  </td>
                );
              });
              if (RowTag === motion.tr) {
                return (
                  <motion.tr key={key} layout="position" transition={{ duration: 0.2, ease: [0.23, 1, 0.32, 1] }} {...extra} data-tone={tone ?? undefined} data-selected={selected || undefined} className={classes}>
                    {cells}
                  </motion.tr>
                );
              }
              return (
                <tr key={key} {...extra} data-tone={tone ?? undefined} data-selected={selected || undefined} className={classes}>
                  {cells}
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
      {scroll.overflow ? (
        // Outside the table, so the cue never covers a header or a value.
        <p aria-hidden="true" className={cn('flex items-center justify-end gap-0.5 px-3 pt-1 pb-1.5 text-2xs text-text-2', stacked && 'max-md:hidden')}>
          {scroll.moreRight ? (
            <>
              More columns, scroll sideways
              <ChevronRight className="size-3.5" />
            </>
          ) : (
            <>
              <ChevronLeft className="size-3.5" />
              Earlier columns, scroll back
            </>
          )}
        </p>
      ) : null}
    </div>
  );
}
