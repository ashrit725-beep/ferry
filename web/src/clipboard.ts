/**
 * Copy to clipboard. The async Clipboard API exists only in secure contexts,
 * and inside a disconnected network the console is often served over plain
 * HTTP on a private address, so a selection-based fallback is kept. The
 * fallback buffer is placed inside an open modal dialog when there is one,
 * because everything outside a modal is inert and cannot be selected.
 */

export async function copyText(text: string, anchor?: Element | null): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or document not focused: try the fallback.
    }
  }
  const host = anchor?.closest('dialog') ?? document.body;
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const buffer = document.createElement('textarea');
  buffer.value = text;
  buffer.setAttribute('readonly', '');
  buffer.setAttribute('aria-hidden', 'true');
  buffer.tabIndex = -1;
  buffer.className = 'clipboard-buffer';
  host.appendChild(buffer);
  let ok = false;
  try {
    buffer.select();
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  } finally {
    buffer.remove();
    previous?.focus();
  }
  return ok;
}
