import baselineSummaryCsv from "../../../experiments/online_baseline_summary.csv?raw";
import baselineByCategoryCsv from "../../../experiments/online_baseline_summary_by_category.csv?raw";
import degradedSummaryCsv from "../../../experiments/online_degraded_summary.csv?raw";
import degradedByCategoryCsv from "../../../experiments/online_degraded_summary_by_category.csv?raw";
import largeAttackSummaryCsv from "../../../experiments/large_attack_summary.csv?raw";
import largeAttackByCategoryCsv from "../../../experiments/large_attack_summary_by_category.csv?raw";

function parseCsv(csv) {
  const lines = csv.trim().split(/\r?\n/).filter(Boolean);
  const headers = lines.shift().split(",");
  return lines.map((line) => {
    const values = line.split(",");
    return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
  });
}

export const experimentResults = {
  baselineSummary: parseCsv(baselineSummaryCsv),
  baselineByCategory: parseCsv(baselineByCategoryCsv),
  degradedSummary: parseCsv(degradedSummaryCsv),
  degradedByCategory: parseCsv(degradedByCategoryCsv),
  largeAttackSummary: parseCsv(largeAttackSummaryCsv),
  largeAttackByCategory: parseCsv(largeAttackByCategoryCsv),
};
