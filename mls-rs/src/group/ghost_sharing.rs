#[derive(Debug, Copy, Clone)]
pub struct GhostSharingParams {
    pub threshold_t: u8,
    pub share_count_m: u8,
}

impl Default for GhostSharingParams {
    fn default() -> Self {
        Self { threshold_t: 3, share_count_m: 8 }
    }
}