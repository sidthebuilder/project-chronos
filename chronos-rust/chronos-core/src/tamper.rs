use std::time::{Duration, Instant};

pub struct AntiTamper {
    last_tick: Instant,
    max_drift: Duration,
    pub anomalies: u32,
}

impl AntiTamper {
    pub fn new(max_drift_ms: u64) -> Self {
        Self {
            last_tick: Instant::now(),
            max_drift: Duration::from_millis(max_drift_ms),
            anomalies: 0,
        }
    }

    /// Returns true if erasure should be triggered (anomaly threshold exceeded).
    pub fn tick(&mut self) -> bool {
        let now = Instant::now();
        let drift = now.duration_since(self.last_tick);
        self.last_tick = now;

        if drift > self.max_drift {
            self.anomalies += 1;
            println!(
                "[ANTI-TAMPER] CPU timing anomaly detected! drift={} ms",
                drift.as_millis()
            );
        }

        if self.anomalies >= 5 {
            println!("[ANTI-TAMPER] Threshold exceeded. Triggering erasure.");
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_no_anomaly_within_threshold() {
        let mut tamper = AntiTamper::new(500);
        let triggered = tamper.tick();
        assert!(!triggered);
        assert_eq!(tamper.anomalies, 0);
    }

    #[test]
    fn test_single_drift_detected() {
        let mut tamper = AntiTamper::new(10);
        sleep(Duration::from_millis(20));
        tamper.tick();
        assert_eq!(tamper.anomalies, 1);
    }

    #[test]
    fn test_erasure_triggers_after_five_anomalies() {
        // 1ms threshold, 50ms sleep — wide margin to survive CI scheduler jitter.
        let mut tamper = AntiTamper::new(1);
        let mut triggered = false;
        for _ in 0..5 {
            sleep(Duration::from_millis(50));
            triggered = tamper.tick();
        }
        assert!(triggered);
        assert!(tamper.anomalies >= 5);
    }
}
