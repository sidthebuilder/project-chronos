use std::time::{Instant, Duration};

pub struct AntiTamper {
    last_tick: Instant,
    max_drift: Duration,
    anomalies: u32,
}

impl AntiTamper {
    pub fn new(max_drift_ms: u64) -> Self {
        Self {
            last_tick: Instant::now(),
            max_drift: Duration::from_millis(max_drift_ms),
            anomalies: 0,
        }
    }

    pub fn tick(&mut self) -> bool {
        let now = Instant::now();
        let drift = now.duration_since(self.last_tick);
        self.last_tick = now;

        if drift > self.max_drift {
            self.anomalies += 1;
            println!("[ANTI-TAMPER] CPU timing anomaly detected! ({} ms)", drift.as_millis());
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
    fn test_anti_tamper_normal() {
        let mut tamper = AntiTamper::new(500);
        let triggered = tamper.tick();
        assert_eq!(triggered, false);
    }

    #[test]
    fn test_anti_tamper_drift() {
        let mut tamper = AntiTamper::new(10);
        // Simulate massive CPU drift
        sleep(Duration::from_millis(15));
        let triggered = tamper.tick();
        assert_eq!(triggered, false);
        assert_eq!(tamper.anomalies, 1);
    }
}
