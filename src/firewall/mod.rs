//! Firewall-слой: бэкенд выбирается один раз для всего процесса.
//!
//! `BCW_FIREWALL=iptables` — iptables-legacy (Android-ядра без NF_TABLES),
//! по умолчанию — nftables. Потребители (pipeline'ы, cmd, orphans) работают с
//! одними и теми же именами `SystemNft`/`SystemNftSync`: это диспетчеры, а не
//! конкретные бэкенды. Правила описывает `nftables` (nft-строки); интерпретируют
//! их `nft::SystemNft` или `iptables::SystemIptables`.

pub mod iptables;
pub mod nft;
pub mod nftables;

pub use nft::{ForeignTable, NftBatch, NftRun, NftRunSync, OwnedTable, OwnedTableMarker, UserConsent};

/// Диспетчер async-исполнителя: бэкенд выбирается при каждом вызове
/// (LazyLock в `iptables::enabled` кеширует само решение).
pub struct SystemNft;

impl NftRun for SystemNft {
    async fn run(&self, batch: NftBatch) -> Result<(), crate::error::BlockcheckError> {
        if iptables::enabled() {
            NftRun::run(&iptables::SystemIptables, batch).await
        } else {
            nft::SystemNft.run(batch).await
        }
    }

    async fn table_names(&self) -> Result<Vec<(String, String)>, crate::error::BlockcheckError> {
        if iptables::enabled() {
            iptables::SystemIptables.table_names().await
        } else {
            nft::SystemNft.table_names().await
        }
    }

    async fn dump_foreign(
        &self,
        table: &ForeignTable,
    ) -> Result<String, crate::error::BlockcheckError> {
        if iptables::enabled() {
            iptables::SystemIptables.dump_foreign(table).await
        } else {
            nft::SystemNft.dump_foreign(table).await
        }
    }
}
/// Диспетчер sync-исполнителя (panic-хуки, идемпотентный вход).
pub struct SystemNftSync;

impl NftRunSync for SystemNftSync {
    fn run(&self, batch: NftBatch) -> Result<(), crate::error::BlockcheckError> {
        if iptables::enabled() {
            NftRunSync::run(&iptables::SystemIptables, batch)
        } else {
            NftRunSync::run(&nft::SystemNftSync, batch)
        }
    }
}
