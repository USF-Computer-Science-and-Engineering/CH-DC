#!/usr/bin/env bash
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "usage: $0 <backup-name>"
  exit 1
fi

work_dir="./k8s-backup"
work_dir_named="${work_dir}/$1"
mkdir -p "$work_dir_named"

resources=(deployments services secrets configmaps ingresses statefulsets daemonsets pvc)

backup_resource() {
  local resource_type="$1"
  local namespace="$2"

  local resource_names
  resource_names="$(kubectl get "$resource_type" -n "$namespace" --no-headers -o custom-columns=":metadata.name" 2>/dev/null || true)"

  for res_name in $resource_names; do
    [ -n "$res_name" ] || continue
    echo "backing up ${resource_type}/${res_name} in namespace ${namespace}..."
    kubectl get "$resource_type" "$res_name" -n "$namespace" -o yaml > "${work_dir_named}/${namespace}/${res_name}-${resource_type}.yaml"
  done
}

namespaces="$(kubectl get namespaces --no-headers -o custom-columns=":metadata.name")"

for namespace in $namespaces; do
  echo "processing namespace: ${namespace}..."
  mkdir -p "${work_dir_named}/${namespace}"

  for resource in "${resources[@]}"; do
    backup_resource "$resource" "$namespace"
  done
done

echo "backing up persistent volumes (global)..."
pvs="$(kubectl get pv --no-headers -o custom-columns=":metadata.name")"
for pv in $pvs; do
  [ -n "$pv" ] || continue
  kubectl get pv "$pv" -o yaml > "${work_dir_named}/${pv}-pv.yaml"
  echo "pv ${pv} backed up."
done

echo "backup complete in ${work_dir_named}"
