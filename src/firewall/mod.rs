//! Firewall-слой.
//!
//! Бэкенд выбирается env `BCW_FIREWALL=iptables` (Android-ядра без
//! CONFIG_NF_TABLES), по умолчанию — nftables. Потребители работают с
//! [`nft::SystemNft`]/[`nft::SystemNftSync`] — это диспетчеры, а не конкретные
//! бэкенды. Правила описывает `nftables` (nft-строки — единственный источник
//! истины); интерпретируют их `nft::NftBackend` или `iptables::SystemIptables`.

pub mod iptables;
pub mod nft;
pub mod nftables;
