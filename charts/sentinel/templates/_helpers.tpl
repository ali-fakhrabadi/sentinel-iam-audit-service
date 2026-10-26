{{- define "sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sentinel.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sentinel.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "sentinel.secretName" -}}
{{- default (printf "%s-secrets" (include "sentinel.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{/* Environment shared by every container running the application image. */}}
{{- define "sentinel.env" -}}
- name: DB_PASSWORD
  valueFrom: {secretKeyRef: {name: {{ include "sentinel.secretName" . }}, key: DB_PASSWORD}}
- name: REDIS_PASSWORD
  valueFrom: {secretKeyRef: {name: {{ include "sentinel.secretName" . }}, key: REDIS_PASSWORD}}
- name: CELERY_BROKER_URL
  value: {{ printf "redis://:$(REDIS_PASSWORD)@%s:%v/%v" .Values.redis.host .Values.redis.port .Values.redis.brokerDb | quote }}
- name: REDIS_CACHE_URL
  value: {{ printf "redis://:$(REDIS_PASSWORD)@%s:%v/%v" .Values.redis.host .Values.redis.port .Values.redis.cacheDb | quote }}
{{- range $key := list "DJANGO_SECRET_KEY" "JWT_SIGNING_KEY" "METRICS_AUTH_TOKEN" "WEBHOOK_SECRET_ENCRYPTION_KEYS" }}
- name: {{ $key }}
  valueFrom: {secretKeyRef: {name: {{ include "sentinel.secretName" $ }}, key: {{ $key }}}}
{{- end }}
{{- end -}}

{{- define "sentinel.podSecurity" -}}
securityContext:
  {{- toYaml .Values.podSecurityContext | nindent 2 }}
automountServiceAccountToken: false
serviceAccountName: {{ include "sentinel.fullname" . }}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "sentinel.tmpVolume" -}}
- name: tmp
  emptyDir: {medium: Memory, sizeLimit: 64Mi}
{{- end -}}
