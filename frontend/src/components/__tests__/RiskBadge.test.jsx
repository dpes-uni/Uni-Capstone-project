import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import RiskBadge from '../RiskBadge.jsx';

describe('RiskBadge', () => {
  it('renders the risk level in lowercase', () => {
    render(<RiskBadge level="HIGH" />);
    expect(screen.getByText('high risk')).toBeInTheDocument();
  });

  it('applies the matching CSS class', () => {
    const { container } = render(<RiskBadge level="medium" />);
    expect(container.querySelector('.risk-badge.risk-medium')).toBeTruthy();
  });

  it('defaults to low risk when no level is given', () => {
    render(<RiskBadge />);
    expect(screen.getByText('low risk')).toBeInTheDocument();
  });
});