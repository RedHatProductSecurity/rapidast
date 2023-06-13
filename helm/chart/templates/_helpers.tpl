{{/*
Expand the name of the chart.
*/}}
{{- define "rapidast-chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "rapidast-chart.fullname" -}}
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
{{- define "rapidast-chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create job spec
*/}}

{{- define "rapidast-chart.job" -}}
template:
  metadata:
    name: {{ .Release.Name }}-job
  spec:
    containers:
    - name: "{{ .Chart.Name }}"
      securityContext: {{ .Values.secContext }}
      image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
      command: ["sh", "-c", "cp /zap/config/helmcustomscan.policy /home/rapidast/.ZAP/policies && rapidast.py --config /zap/config/rapidastconfig.yaml"]
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      volumeMounts:
      - name: config-volume
        mountPath: /zap/config
      - name: results-volume
        mountPath: /home/rapidast/results/
    volumes:
      - name: config-volume
        configMap:
          name: {{ .Release.Name }}-configmap
      - name: results-volume
        persistentVolumeClaim:
          claimName: {{ .Values.pvc }}
    restartPolicy: Never
{{- end }}
