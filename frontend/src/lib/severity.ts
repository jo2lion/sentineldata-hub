/**
 * Shared severity-tier classification.
 *
 * Extracted here because ThreatAnalytics.tsx's Risk Composition donut is
 * this classification's THIRD consumer alongside CveMetricsGrid's table
 * (App.tsx). riskTone() and matchesRiskFilter() in App.tsx are a fourth and
 * fifth call site sharing the exact same 5.0/4.0/3.0 thresholds, but return
 * different shapes (a Tailwind class string, and a 3-bucket boolean
 * respectively) for different reasons -- see the comment above
 * CveMetricsGrid in App.tsx for why those two were deliberately left
 * un-refactored. If backend/app/data/pipeline.py's _process_batch risk
 * tiers ever change, all five call sites need to change together, and
 * nothing enforces that -- flagged repeatedly across tickets, still not
 * unified across all five in this pass either.
 */

export type SeverityTier = "Critical" | "High" | "Medium" | "Low";

export const SEVERITY_TIERS: readonly SeverityTier[] = ["Critical", "High", "Medium", "Low"];

export function classifySeverityTier(riskScore: number): SeverityTier {
  if (riskScore >= 5.0) return "Critical";
  if (riskScore >= 4.0) return "High";
  if (riskScore >= 3.0) return "Medium";
  return "Low";
}

/**
 * Tailwind text-color classes -- for CveMetricsGrid's plain-DOM table,
 * where Tailwind classes apply normally.
 */
export const SEVERITY_TIER_TEXT_CLASS: Record<SeverityTier, string> = {
  Critical: "text-signal-critical",
  High: "text-signal-warning",
  Medium: "text-signal-warning/70",
  Low: "text-signal-ok",
};

/**
 * Literal CSS custom-property references (NOT Tailwind classes) -- for
 * recharts' Cell/stroke/fill props in ThreatAnalytics.tsx, which recharts
 * renders as raw SVG attributes outside Tailwind's class-scanning pipeline
 * entirely, so a `text-signal-critical`-style className would silently do
 * nothing there. Tailwind v4's `@theme` block in index.css compiles
 * --color-signal-* into real CSS custom properties on :root regardless of
 * whether any utility class ever references them, so `var(--color-...)`
 * resolves correctly here exactly as it would in a plain stylesheet.
 *
 * These deliberately reuse the EXACT same four severity colors
 * SEVERITY_TIER_TEXT_CLASS already uses for the table: the donut and the
 * table represent the SAME four categories, and giving one category a
 * different color in two visualizations on the same page is exactly the
 * "color follows the entity, not its rendering context" violation this
 * project's dataviz conventions rule out.
 */
export const SEVERITY_TIER_CHART_COLOR: Record<SeverityTier, string> = {
  Critical: "var(--color-signal-critical)",
  High: "var(--color-signal-warning)",
  // Medium reuses the warning hue at reduced opacity, matching
  // SEVERITY_TIER_TEXT_CLASS's "text-signal-warning/70" exactly. recharts
  // has no Tailwind opacity-modifier equivalent for a raw color string, so
  // this spells out the same color-mix() Tailwind v4 itself generates for
  // `/70` opacity modifiers (confirmed in an earlier pass this session),
  // rather than a separately-guessed, possibly-inconsistent hex value.
  Medium: "color-mix(in oklab, var(--color-signal-warning) 70%, transparent)",
  Low: "var(--color-signal-ok)",
};
