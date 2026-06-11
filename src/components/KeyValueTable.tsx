type Props = {
  title?: string;
  rows: Array<{ label: string; value: React.ReactNode; mono?: boolean }>;
};

export function KeyValueTable({ title, rows }: Props) {
  return (
    <div className="kv">
      {title && <h3>{title}</h3>}
      <table>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label}>
              <th>{row.label}</th>
              <td className={row.mono ? 'mono' : undefined}>{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
