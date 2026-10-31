import { useSyncExternalStore } from "react"

export type ResolvedTheme = "light" | "dark"

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] })
  return () => observer.disconnect()
}

function read(): ResolvedTheme {
  return document.documentElement.classList.contains("dark") ? "dark" : "light"
}

/**
 * The theme the console is rendering, read from the `dark` class on <html>
 * (the `dark` custom variant in index.css). Replaces next-themes, which keeps
 * its choice in localStorage and injects an inline script: both are off-limits
 * under the gateway's Content-Security-Policy.
 */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, read, () => "light")
}
