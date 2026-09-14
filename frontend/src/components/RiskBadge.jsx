import React from 'react';

export default function RiskBadge({ level }) {
  const normalized = (level || 'low').toLowerCase();
  return <span className={`risk-badge risk-${normalized}`}>{normalized} risk</span>;
}
