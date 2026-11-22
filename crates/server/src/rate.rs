use std::{collections::HashMap, net::IpAddr, sync::Mutex};

use crate::storage::{Error, Result};

const HOUR: i64 = 3600;

pub(crate) struct RateLimiter {
    limit: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

struct Bucket {
    // One create costs HOUR credits, and limit credits accrue every second.
    credits: i64,
    updated: i64,
}

impl RateLimiter {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn spend(&self, ip: IpAddr, now: i64) -> Result<()> {
        if self.limit == 0 {
            return Err(Error::RateLimited { retry_after: HOUR });
        }
        let limit = i64::from(self.limit);
        let capacity = HOUR * limit;
        let mut buckets = self.buckets.lock().map_err(|_| Error::Internal)?;
        let network = match ip.to_canonical() {
            IpAddr::V4(ip) => IpAddr::V4(ip),
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & (u128::MAX << 64)).into()),
        };
        let bucket = buckets.entry(network).or_insert(Bucket {
            credits: capacity,
            updated: now,
        });
        let elapsed = now.saturating_sub(bucket.updated).clamp(0, HOUR);
        bucket.credits = (bucket.credits + elapsed * limit).min(capacity);
        bucket.updated = bucket.updated.max(now);
        if bucket.credits < HOUR {
            let refill_seconds = (HOUR - bucket.credits + limit - 1) / limit;
            let clock_skew = bucket.updated.saturating_sub(now);
            return Err(Error::RateLimited {
                retry_after: refill_seconds.saturating_add(clock_skew),
            });
        }
        bucket.credits -= HOUR;
        Ok(())
    }

    pub fn sweep(&self, now: i64) -> Result<()> {
        self.buckets
            .lock()
            .map_err(|_| Error::Internal)?
            .retain(|_, bucket| now.saturating_sub(bucket.updated) < HOUR);
        Ok(())
    }
}
