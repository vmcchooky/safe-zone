import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Bounded pagination window: the page count can come straight from a server
 * response, and a corrupt or absurd total (e.g. Number.MAX_SAFE_INTEGER)
 * must not materialize that many page buttons — building the full list with
 * Array.from({ length }) crashes the app outright (RangeError). Returns at
 * most 7 page numbers; `null` marks an ellipsis gap between ranges.
 */
export function paginationWindow(current: number, total: number): Array<number | null> {
  const totalPages = Math.max(1, Math.floor(total) || 1);
  const currentPage = Math.min(Math.max(1, Math.floor(current) || 1), totalPages);
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  const pages = new Set<number>();
  for (const p of [1, totalPages, currentPage - 1, currentPage, currentPage + 1]) {
    if (p >= 1 && p <= totalPages) pages.add(p);
  }
  if (currentPage <= 3) [2, 3, 4].forEach((p) => pages.add(p));
  if (currentPage >= totalPages - 2) {
    [totalPages - 3, totalPages - 2, totalPages - 1].forEach((p) => pages.add(p));
  }
  const ordered = Array.from(pages).sort((a, b) => a - b);
  const window: Array<number | null> = [];
  let prev = 0;
  for (const p of ordered) {
    if (p - prev > 1) window.push(null);
    window.push(p);
    prev = p;
  }
  return window;
}
