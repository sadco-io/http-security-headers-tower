//! Security policy types.
//!
//! This module contains all the policy types for various security headers.

pub mod cross_origin;
pub mod csp;
pub mod frame_options;
pub mod hsts;
pub mod nonce;
pub mod permissions_policy;
pub mod referrer;

pub use cross_origin::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
};
pub use csp::ContentSecurityPolicy;
pub use frame_options::XFrameOptions;
pub use hsts::StrictTransportSecurity;
pub use nonce::Nonce;
pub use permissions_policy::PermissionsPolicy;
pub use referrer::ReferrerPolicy;
