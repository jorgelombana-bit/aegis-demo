import { useState } from 'react';

type Props = {
  data: unknown;
  /** Initial depth to expand. 0 = collapsed root, Infinity = fully expanded. */
  initialDepth?: number;
  /** Optional className for the root container. */
  className?: string;
};

type JsonValue =
  | { kind: 'object'; entries: Array<[string, JsonValue]>; length: number }
  | { kind: 'array'; items: JsonValue[]; length: number }
  | { kind: 'primitive'; display: string };

function toJsonValue(value: unknown, seen: WeakSet<object>): JsonValue {
  if (value === null) return { kind: 'primitive', display: 'null' };
  if (value === undefined) return { kind: 'primitive', display: 'undefined' };

  const t = typeof value;
  if (t === 'string') return { kind: 'primitive', display: JSON.stringify(value) };
  if (t === 'number') return { kind: 'primitive', display: Number.isFinite(value as number) ? String(value) : 'null' };
  if (t === 'boolean') return { kind: 'primitive', display: String(value) };
  if (t === 'bigint') return { kind: 'primitive', display: `${value.toString()}n` };
  if (t === 'function') return { kind: 'primitive', display: '[Function]' };
  if (t === 'symbol') return { kind: 'primitive', display: value.toString() };

  if (value instanceof Uint8Array) {
    return { kind: 'primitive', display: `Uint8Array(${value.length})` };
  }
  if (value instanceof Date) {
    return { kind: 'primitive', display: value.toISOString() };
  }

  if (seen.has(value as object)) {
    return { kind: 'primitive', display: '[Circular]' };
  }
  seen.add(value as object);

  if (Array.isArray(value)) {
    return {
      kind: 'array',
      items: value.map((v) => toJsonValue(v, seen)),
      length: value.length,
    };
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const entries = Object.entries(obj).map<[string, JsonValue]>(([k, v]) => [k, toJsonValue(v, seen)]);
    return { kind: 'object', entries, length: entries.length };
  }

  return { kind: 'primitive', display: String(value) };
}

type NodeProps = {
  value: JsonValue;
  keyName?: string;
  depth: number;
  isLast: boolean;
  maxDepth: number;
};

function JsonNode({ value, keyName, depth, isLast, maxDepth }: NodeProps) {
  if (value.kind === 'primitive') {
    return (
      <span className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-colon">: </span>}
        <span className={`json-${scalarClass(value.display)}`}>{value.display}</span>
        {!isLast && <span className="json-comma">,</span>}
      </span>
    );
  }

  if (value.kind === 'array') {
    if (value.length === 0) {
      return (
        <span className="json-line">
          {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
          {keyName !== undefined && <span className="json-colon">: </span>}
          <span className="json-bracket">[]</span>
          {!isLast && <span className="json-comma">,</span>}
        </span>
      );
    }
    return (
      <Collapsible
        keyName={keyName}
        isLast={isLast}
        openByDefault={depth < maxDepth}
        bracket="[]"
        length={value.length}
      >
        {value.items.map((item, i) => (
          <JsonNode
            key={i}
            value={item}
            depth={depth + 1}
            isLast={i === value.items.length - 1}
            maxDepth={maxDepth}
          />
        ))}
      </Collapsible>
    );
  }

  // object
  if (value.length === 0) {
    return (
      <span className="json-line">
        {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
        {keyName !== undefined && <span className="json-colon">: </span>}
        <span className="json-bracket">{'{}'}</span>
        {!isLast && <span className="json-comma">,</span>}
      </span>
    );
  }
  return (
    <Collapsible
      keyName={keyName}
      isLast={isLast}
      openByDefault={depth < maxDepth}
      bracket="{}"
      length={value.length}
    >
      {value.entries.map(([k, v], i) => (
        <JsonNode
          key={k}
          value={v}
          keyName={k}
          depth={depth + 1}
          isLast={i === value.entries.length - 1}
          maxDepth={maxDepth}
        />
      ))}
    </Collapsible>
  );
}

function scalarClass(display: string): 'string' | 'number' | 'boolean' | 'null' | 'other' {
  if (display === 'null' || display === 'undefined') return 'null';
  if (display === 'true' || display === 'false') return 'boolean';
  if (display.startsWith('"') && display.endsWith('"')) return 'string';
  if (/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(display)) return 'number';
  return 'other';
}

type CollapsibleProps = {
  keyName?: string;
  isLast: boolean;
  openByDefault: boolean;
  bracket: '{}' | '[]';
  length: number;
  children: React.ReactNode;
};

function Collapsible({ keyName, isLast, openByDefault, bracket, length, children }: CollapsibleProps) {
  const [open, setOpen] = useState(openByDefault);
  const openChar = bracket[0];
  const closeChar = bracket[1];

  return (
    <span className="json-line json-collapsible">
      {keyName !== undefined && <span className="json-key">"{keyName}"</span>}
      {keyName !== undefined && <span className="json-colon">: </span>}
      <button
        type="button"
        className="json-toggle"
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? 'Collapse' : 'Expand'}
        title={`${open ? 'Collapse' : 'Expand'} ${length} ${bracket === '[]' ? 'item' : 'field'}${length === 1 ? '' : 's'}`}
      >
        <span className="json-caret">{open ? '−' : '+'}</span>
        <span className="json-bracket">{openChar}</span>
        {!open && (
          <span className="json-summary">
            {' '}
            {bracket === '[]' ? `${length} item${length === 1 ? '' : 's'}` : `${length} field${length === 1 ? '' : 's'}`}
            <span className="json-bracket">{closeChar}</span>
          </span>
        )}
      </button>
      {!open && !isLast && <span className="json-comma">,</span>}
      {open && (
        <div className="json-children">
          {children}
        </div>
      )}
      {open && (
        <div className="json-close">
          <span className="json-bracket">{closeChar}</span>
          {!isLast && <span className="json-comma">,</span>}
        </div>
      )}
    </span>
  );
}

export function JsonView({ data, initialDepth = 2, className }: Props) {
  const [copied, setCopied] = useState(false);
  const parsed = toJsonValue(data, new WeakSet());
  const text = JSON.stringify(data, (_k, v) => (v instanceof Uint8Array ? `Uint8Array(${v.length})` : v), 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className={`json-view ${className ?? ''}`}>
      <div className="json-view-toolbar">
        <span className="json-view-label">JSON</span>
        <button type="button" className="json-view-copy" onClick={handleCopy} title="Copy raw JSON">
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <div className="json-tree">
        <JsonNode value={parsed} depth={0} isLast maxDepth={initialDepth} />
      </div>
    </div>
  );
}
