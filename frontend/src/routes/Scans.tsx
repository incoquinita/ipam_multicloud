import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCw, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Badge } from "@/components/ui/Badge";
import { Dialog, DialogContent } from "@/components/ui/Dialog";
import { ScanForm } from "@/components/scans/ScanForm";
import { formatDate } from "@/lib/utils";
import { useScans } from "@/hooks/useScans";
import type { Scan as ScanType } from "@/types/scan";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/ui/DataTable";

export function Scans() {
  const { data, isLoading, refetch, isFetching } = useScans({
    page: 1,
    size: 20,
  });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [newScanOpen, setNewScanOpen] = useState(false);

  const columns: ColumnDef<ScanType>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => (
        <button
          type="button"
          onClick={() => navigate(`/scans/${row.original.id}/results`)}
          className="text-left font-medium text-surface-100 transition-colors hover:text-brand-300"
        >
          {row.getValue("name")}
        </button>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => <StatusBadge status={row.getValue("status")} />,
    },
    {
      accessorKey: "scan_type",
      header: "Type",
      cell: ({ row }) => (
        <Badge variant="info">{row.getValue("scan_type")}</Badge>
      ),
    },
    {
      accessorKey: "progress",
      header: "Progress",
      cell: ({ row }) => {
        const progress = row.getValue("progress") as number;
        return (
          <div className="flex items-center gap-2">
            <div className="max-w-[100px] h-1.5 flex-1 rounded-full bg-surface-800">
              <div
                className="h-full rounded-full bg-brand-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-xs text-surface-400">{progress}%</span>
          </div>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ row }) => (
        <span className="text-surface-400">
          {formatDate(row.getValue("created_at"))}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate(`/scans/${row.original.id}/results`)}
        >
          View
          <ArrowRight className="ml-1 h-3.5 w-3.5" />
        </Button>
      ),
    },
  ];

  const handleRefresh = () => {
    // Force a fresh network request rather than serving cached data.
    void refetch();
  };

  const handleScanCreated = () => {
    setNewScanOpen(false);
    // Invalidate every scans query so all open views reconcile.
    void queryClient.invalidateQueries({ queryKey: ["scans"] });
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-surface-50">Scans</h1>
          <p className="text-sm text-surface-400 mt-1">
            Manage and monitor security scans
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isFetching}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isFetching ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Button size="sm" onClick={() => setNewScanOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Scan
          </Button>
        </div>
      </div>

      {/* New scan dialog */}
      <Dialog open={newScanOpen} onOpenChange={setNewScanOpen}>
        <DialogContent
          title="New Scan"
          description="Configure a target, profile, and options to start a scan."
          className="max-w-2xl max-h-[90vh] overflow-y-auto"
        >
          <ScanForm onSuccess={handleScanCreated} />
        </DialogContent>
      </Dialog>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <RefreshCw className="h-6 w-6 animate-spin text-surface-500" />
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          pageSize={20}
        />
      )}
    </div>
  );
}
