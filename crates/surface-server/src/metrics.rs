use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub(crate) authentication_failures: AtomicU64,
    pub(crate) jobs_completed: AtomicU64,
    pub(crate) jobs_failed: AtomicU64,
    pub(crate) notification_attempts: AtomicU64,
    pub(crate) notification_failures: AtomicU64,
}

impl Metrics {
    pub(crate) fn increment(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "# TYPE surface_authentication_failures_total counter\nsurface_authentication_failures_total {}\n\
# TYPE surface_jobs_completed_total counter\nsurface_jobs_completed_total {}\n\
# TYPE surface_jobs_failed_total counter\nsurface_jobs_failed_total {}\n\
# TYPE surface_notification_attempts_total counter\nsurface_notification_attempts_total {}\n\
# TYPE surface_notification_failures_total counter\nsurface_notification_failures_total {}\n",
            self.authentication_failures.load(Ordering::Relaxed),
            self.jobs_completed.load(Ordering::Relaxed),
            self.jobs_failed.load(Ordering::Relaxed),
            self.notification_attempts.load(Ordering::Relaxed),
            self.notification_failures.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn metrics_have_only_fixed_labels() {
        let metrics = Metrics::default().render();
        assert!(!metrics.contains('{'));
        assert!(!metrics.contains("target"));
        assert!(!metrics.contains("tenant"));
    }
}
