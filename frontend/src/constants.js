// ─── Shared Document Metadata ─────────────────────────────────────────────────
// Single source of truth for document types across all pages

export const DOC_META = {
  datasheet:    { label: 'Datasheet',    icon: '📄', color: '#5252e0' },
  aadhaar:      { label: 'Aadhaar',      icon: '🪪', color: '#8b5cf6' },
  pan:          { label: 'PAN Card',     icon: '💳', color: '#ec4899' },
  bank_account: { label: 'Bank Account', icon: '🏦', color: '#f59e0b' },
}

export const DOC_TYPES = [
  { key: 'datasheet',    label: 'Datasheet',    icon: '📄', required: true },
  { key: 'aadhaar',      label: 'Aadhaar',      icon: '🪪', required: false },
  { key: 'pan',          label: 'PAN Card',     icon: '💳', required: false },
  { key: 'bank_account', label: 'Bank Account', icon: '🏦', required: false },
]

export const DOC_TYPE_KEYS = DOC_TYPES.map(d => d.key)
