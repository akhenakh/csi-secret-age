{{/*
Expand the name of the chart.
*/}}
{{- define "csi-secret-age.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "csi-secret-age.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "csi-secret-age.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "csi-secret-age.labels" -}}
helm.sh/chart: {{ include "csi-secret-age.chart" . }}
{{ include "csi-secret-age.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "csi-secret-age.selectorLabels" -}}
app.kubernetes.io/name: {{ include "csi-secret-age.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Namespace to use for resources
*/}}
{{- define "csi-secret-age.namespace" -}}
{{- if .Values.namespace }}
{{- .Values.namespace }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
RBAC namespace
*/}}
{{- define "csi-secret-age.rbacNamespace" -}}
{{- if .Values.namespace }}
{{- .Values.namespace }}
{{- else if .Release.Namespace }}
{{- .Release.Namespace }}
{{- else }}
{{- "kube-system" }}
{{- end }}
{{- end }}
