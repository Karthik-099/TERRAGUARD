{{- define "terraguard.labels" -}}
app.kubernetes.io/name: terraguard
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- define "terraguard.selector" -}}
app.kubernetes.io/name: terraguard
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
