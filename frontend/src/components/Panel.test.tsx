import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiTable, LoadError, Loading } from './Panel';

describe('shared data components', () => {
  it('renders a loading state with an accessible status role', () => {
    render(<Loading />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading SAM data');
  });

  it('renders server errors with an explicit retry action', async () => {
    const retry = vi.fn();
    render(<LoadError message="API unavailable" retry={retry} />);
    expect(screen.getByText('API unavailable')).toBeInTheDocument();
    screen.getByRole('button', { name: 'Retry' }).click();
    expect(retry).toHaveBeenCalledOnce();
  });

  it('renders server-provided rows and an honest empty state', () => {
    const { rerender } = render(<ApiTable rows={[{ id: 'ASSET-1', name: 'portal.example' }]} columns={[{ key: 'name', label: 'Asset' }]} />);
    expect(screen.getByRole('cell', { name: 'portal.example' })).toBeInTheDocument();
    rerender(<ApiTable rows={[]} columns={[{ key: 'name', label: 'Asset' }]} />);
    expect(screen.getByText('No records are available for this view.')).toBeInTheDocument();
  });
});
