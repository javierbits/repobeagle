from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

trace.set_tracer_provider(TracerProvider())

import sentry_sdk
sentry_sdk.set_user({"id": current_user.id})

posthog.opt_out_capturing()
