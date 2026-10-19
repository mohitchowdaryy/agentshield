// Chart colors validated with the dataviz palette validator against the dark surface (#0a0f1c).
// Outcome palette: lightness band, chroma, contrast pass; adjacent CVD separation is in the warn band,
// so outcome charts always carry a legend and direct value labels (never color alone).
import { Bar, BarChart, CartesianGrid, Cell, LabelList, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const OUTCOME_ORDER = ["failed", "inconclusive", "succeeded", "errored"] as const;
export const OUTCOME_CHART: Record<string, string> = {
  failed: "#1fa97a",
  inconclusive: "#b8891f",
  succeeded: "#e0435f",
  errored: "#b65ad0",
};
export const OUTCOME_LABEL: Record<string, string> = {
  failed: "attack failed",
  inconclusive: "inconclusive",
  succeeded: "attack succeeded",
  errored: "errored",
};
// Severity is ordinal: one hue, stepped by intensity; identity is carried by the axis label.
export const SEVERITY_RAMP: Record<string, string> = {
  critical: "#f0506e",
  high: "#c4435d",
  medium: "#963a4f",
  low: "#6c3142",
  info: "#4b2a36",
};

const SEV_SHORT: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };

const axis = { stroke: "#2a3a5c", tick: { fill: "#a5b0cb", fontSize: 11 }, tickLine: false };
const tooltipStyle = {
  contentStyle: { background: "#0e1526", border: "1px solid #2a3a5c", borderRadius: 8, fontSize: 12, color: "#e4e9f5" },
  itemStyle: { color: "#e4e9f5" },
  labelStyle: { color: "#a5b0cb" },
  cursor: { fill: "rgba(125,139,173,0.08)" },
};

export function SeverityBars({ data }: { data: { severity: string; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 18, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="#1d2943" />
        <XAxis dataKey="severity" interval={0} {...axis} tickFormatter={(v: string) => SEV_SHORT[v] ?? v} />
        <YAxis allowDecimals={false} {...axis} axisLine={false} />
        <Tooltip {...tooltipStyle} formatter={(v) => [v, "open findings"]} labelFormatter={(l) => `severity: ${l}`} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={44}>
          {data.map((d) => (
            <Cell key={d.severity} fill={SEVERITY_RAMP[d.severity]} />
          ))}
          <LabelList dataKey="count" position="top" fill="#a5b0cb" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function OutcomeByMode({ data }: { data: Record<string, number | string>[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }} barCategoryGap={18}>
        <CartesianGrid horizontal={false} stroke="#1d2943" />
        <XAxis type="number" allowDecimals={false} {...axis} />
        <YAxis type="category" dataKey="mode" width={84} {...axis} axisLine={false} />
        <Tooltip {...tooltipStyle} />
        <Legend
          formatter={(v: string) => <span style={{ color: "#a5b0cb", fontSize: 11 }}>{OUTCOME_LABEL[v] ?? v}</span>}
          iconType="square"
          iconSize={9}
        />
        {OUTCOME_ORDER.map((o) => (
          <Bar key={o} dataKey={o} name={o} stackId="a" fill={OUTCOME_CHART[o]} stroke="#0a0f1c" strokeWidth={2}>
            <LabelList dataKey={o} position="center" fill="#ffffff" fontSize={11} formatter={(v: unknown) => (v ? String(v) : "")} />
          </Bar>
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CountBars({ data, label, color = "#5b7cfa" }: { data: { key: string; count: number }[]; label: string; color?: string }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 18, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="#1d2943" />
        <XAxis dataKey="key" interval={0} {...axis} />
        <YAxis allowDecimals={false} {...axis} axisLine={false} />
        <Tooltip {...tooltipStyle} formatter={(v) => [v, label]} />
        <Bar dataKey="count" fill={color} radius={[4, 4, 0, 0]} maxBarSize={44}>
          <LabelList dataKey="count" position="top" fill="#a5b0cb" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
