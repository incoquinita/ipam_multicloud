import { useProviders } from "@/hooks/useProviders";
import { Badge } from "@/components/ui/Badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Cloud, CheckCircle, XCircle } from "lucide-react";

export function CloudStatus() {
  const { data, isLoading } = useProviders();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cloud Providers</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <p className="text-sm text-surface-500">Loading providers...</p>
          </div>
        ) : !data?.items?.length ? (
          <div className="flex items-center justify-center py-8">
            <p className="text-sm text-surface-500">No providers configured.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {data.items.map((provider) => (
              <div
                key={provider.id}
                className="flex items-center justify-between rounded-lg border border-surface-800 bg-surface-950 p-3"
              >
                <div className="flex items-center gap-3">
                  <Cloud className="h-5 w-5 text-brand-500" />
                  <div>
                    <p className="text-sm font-medium text-surface-100">
                      {provider.name}
                    </p>
                    <p className="text-xs text-surface-400">
                      {provider.provider_type.toUpperCase()}
                      {provider.regions?.length
                        ? ` · ${provider.regions.length} regions`
                        : ""}
                    </p>
                  </div>
                </div>
                {provider.is_configured ? (
                  <Badge variant="success">
                    <CheckCircle className="mr-1 h-3 w-3" />
                    Connected
                  </Badge>
                ) : (
                  <Badge variant="warning">
                    <XCircle className="mr-1 h-3 w-3" />
                    Unconfigured
                  </Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
