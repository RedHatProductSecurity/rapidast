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
      # Since Helm configmap cannot handle the dash character but the policy name undner  scanPolicyXML' in 'values.yaml' is 'helm-custom-scan', the dest file name of the copy command is 'helm-custom-scan.policy'.
      # This file will be used if the rapidast config specifies 'helm-custom-scan' for the activeScan policy.
      # Otherwise, '/home/rapidast/.ZAP/policies/API-scan-minimal.policy' will be used by default.
      command: ["sh", "-c", "cp /helm/config/helmcustomscan.policy /home/rapidast/.ZAP/policies/helm-custom-scan.policy && rapidast.py --config /helm/config/rapidastconfig.yaml"]
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      volumeMounts:
      - name: config-volume
        mountPath: /helm/config
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
