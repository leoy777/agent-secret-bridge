use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use tokio::sync::Mutex;

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct RateLimiter {
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub async fn check(&self, capability_id: &str, maximum: u32) -> Result<()> {
        let now = Instant::now();
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        let mut calls = self.calls.lock().await;
        let capability_calls = calls.entry(capability_id.to_owned()).or_default();
        while capability_calls.front().is_some_and(|call| *call <= cutoff) {
            capability_calls.pop_front();
        }
        if capability_calls.len() >= maximum as usize {
            bail!(
                "capability {capability_id:?} exceeded its limit of {maximum} requests per minute"
            );
        }
        capability_calls.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn denies_calls_above_capability_limit() {
        let limiter = RateLimiter::default();
        limiter.check("one", 2).await.unwrap();
        limiter.check("one", 2).await.unwrap();
        assert!(limiter.check("one", 2).await.is_err());
        limiter.check("two", 1).await.unwrap();
    }
}
