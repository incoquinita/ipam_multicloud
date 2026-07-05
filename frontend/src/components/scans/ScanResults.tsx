import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import type { ScanResult } from "@/types/scan";

interface ScanResultsProps {
  results: ScanResult[];
}

export function ScanResults({ results }: ScanResultsProps) {
  if (!results.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Results</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <p className="text-sm text-surface-500">No results available.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Results</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {results.map((result) => (
            <div
              key={result.id}
              className="rounded-lg border border-surface-800 bg-surface-950 p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-surface-100">
                  {result.host}
                </span>
                <Badge
                  variant={result.state === "up" ? "success" : "default"}
                >
                  {result.state}
                </Badge>
              </div>
              {result.ports.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.ports.map((port, i) => (
                    <Badge
                      key={`${port.port}-${i}`}
                      variant={
                        port.state === "open"
                          ? "warning"
                          : port.state === "filtered"
                            ? "info"
                            : "default"
                      }
                    >
                      {port.port}/{port.protocol}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
