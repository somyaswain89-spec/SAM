import type { ReactNode } from 'react';

export function PageHeader({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return <div className="page-header"><div><p className="eyebrow">SECURITY EXPOSURE MANAGEMENT</p><h1>{title}</h1><p className="muted">{description}</p></div><div className="actions">{actions}</div></div>;
}

export function Panel({ title, children, className = '' }: { title?: string; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{title && <h2>{title}</h2>}{children}</section>;
}

export function LoadError({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="notice error"><strong>Unable to load this data.</strong><span>{message}</span>{retry && <button onClick={retry}>Retry</button>}</div>;
}

export function Loading() { return <div className="loading" role="status">Loading SAM data…</div>; }

export function Empty({ children = 'No records are available for this view.' }: { children?: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ApiTable<T extends object>({ rows, columns }: { rows: T[]; columns: Array<{ key: keyof T | string; label: string }> }) {
  if (!rows.length) return <Empty />;
  return <div className="table-scroll"><table><thead><tr>{columns.map((column) => <th key={String(column.key)}>{column.label}</th>)}</tr></thead><tbody>
    {rows.map((row, index) => <tr key={String((row as Record<string, unknown>).id ?? index)}>{columns.map((column) => {
      const value = (row as Record<string, unknown>)[String(column.key)];
      return <td key={String(column.key)}>{value === null || value === undefined || value === '' ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value)}</td>;
    })}</tr>)}
  </tbody></table></div>;
}

export function Metric({ label, value, footnote }: { label: string; value: ReactNode; footnote?: ReactNode }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong>{footnote && <small>{footnote}</small>}</div>;
}
