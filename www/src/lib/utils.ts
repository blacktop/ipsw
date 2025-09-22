import { type ClassValue, clsx } from "clsx"

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs)
}

export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return '0 Bytes'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number,
  immediate?: boolean
): ((...args: Parameters<T>) => void) & { cancel: () => void } {
  let timeout: NodeJS.Timeout | null = null

  const debouncedFunction = function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null
      if (!immediate) func(...args)
    }

    const callNow = immediate && !timeout

    if (timeout) clearTimeout(timeout)
    timeout = setTimeout(later, wait)

    if (callNow) func(...args)
  }

  debouncedFunction.cancel = () => {
    if (timeout) {
      clearTimeout(timeout)
      timeout = null
    }
  }

  return debouncedFunction
}

export function truncateText(text: string, maxLength: number) {
  if (text.length <= maxLength) return text
  return text.slice(0, maxLength) + '...'
}

export function highlightSearchTerm(text: string, searchTerm: string) {
  if (!searchTerm) return text

  const regex = new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
  return text.replace(regex, '<mark class="bg-primary/20 text-primary">$1</mark>')
}

export function formatEntitlementValue(value: any, type: string): string {
  switch (type) {
    case 'bool':
      return value ? 'true' : 'false'
    case 'number':
      return value?.toString() || '0'
    case 'string':
      return value || ''
    case 'array':
      try {
        const arrayValue = typeof value === 'string' ? JSON.parse(value) : value
        return Array.isArray(arrayValue) ? arrayValue.join(', ') : value
      } catch {
        return value || ''
      }
    case 'dict':
    case 'object':
      try {
        const dictValue = typeof value === 'string' ? JSON.parse(value) : value
        return typeof dictValue === 'object' ? JSON.stringify(dictValue, null, 2) : value
      } catch {
        return value || ''
      }
    default:
      return value?.toString() || ''
  }
}

export function getValueTypeColor(type: string): string {
  switch (type) {
    case 'bool':
      return 'var(--ifm-color-danger)'
    case 'number':
      return 'var(--ifm-color-warning)'
    case 'string':
      return 'var(--ifm-color-success)'
    case 'array':
      return 'var(--ifm-color-info)'
    case 'dict':
    case 'object':
      return 'var(--ifm-color-primary)'
    default:
      return 'var(--ifm-color-content-secondary)'
  }
}

export function sortVersions(versions: string[]): string[] {
  return versions.sort((a, b) => {
    const aParts = a.split('.').map(Number)
    const bParts = b.split('.').map(Number)

    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      const aPart = aParts[i] || 0
      const bPart = bParts[i] || 0

      if (aPart !== bPart) {
        return bPart - aPart // Descending order
      }
    }

    return 0
  })
}
