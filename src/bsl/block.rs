use super::len::{parse_len, Len};
use crate::bsl::{BlockHeader, Transaction};
use crate::{ParseResult, SResult, Visit, Visitor};

/// A Bitcoin block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<'a> {
    slice: &'a [u8],
    header: BlockHeader<'a>,
    total_txs: usize,
}

impl<'a> Visit<'a> for Block<'a> {
    fn visit<'b, V: Visitor>(slice: &'a [u8], visit: &'b mut V) -> SResult<'a, Self> {
        let header = BlockHeader::visit(slice, visit)?;
        let Len { mut consumed, n } = parse_len(header.remaining())?;
        consumed += 80;
        let total_txs = n as usize;
        let mut remaining = &slice[consumed..];

        visit.visit_block_begin(total_txs);
        for _ in 0..total_txs {
            let tx = Transaction::visit(remaining, visit)?;
            remaining = tx.remaining();
            consumed += tx.consumed();
        }

        let (slice, remaining) = slice.split_at(consumed);
        let parsed = Block {
            slice,
            header: header.parsed_owned(),
            total_txs,
        };
        Ok(ParseResult::new(remaining, parsed))
    }
}

impl<'a> Block<'a> {
    /// Returns the hash of this block
    #[cfg(feature = "groestlcoin_hashes")]
    pub fn block_hash(&self) -> crate::groestlcoin_hashes::groestld::Hash {
        self.header.block_hash()
    }

    /// Calculate the block hash using the sha2 crate.
    /// NOTE: the result type is not displayed backwards when converted to string.
    #[cfg(feature = "sha2")]
    pub fn block_hash_sha2(
        &self,
    ) -> crate::sha2::digest::generic_array::GenericArray<u8, crate::sha2::digest::typenum::U32>
    {
        self.header.block_hash_sha2()
    }

    /// Returns the total transactions in this block
    pub fn total_transactions(&self) -> usize {
        self.total_txs
    }

    /// Returns the header in this block
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
}

impl<'a> AsRef<[u8]> for Block<'a> {
    fn as_ref(&self) -> &[u8] {
        self.slice
    }
}

#[cfg(all(feature = "groestlcoin", feature = "sha2"))]
pub mod visitor {
    use core::ops::ControlFlow;

    use groestlcoin::consensus::Decodable;
    use groestlcoin::hashes::Hash;

    /// Implement a visitor to find a Transaction in a Block given its txid
    pub struct FindTransaction {
        to_find: groestlcoin::Txid,
        tx_found: Option<groestlcoin::Transaction>,
    }
    impl FindTransaction {
        /// Creates [`FindTransaction`] for txid `to_find`
        pub fn new(to_find: groestlcoin::Txid) -> Self {
            Self {
                to_find,
                tx_found: None,
            }
        }
        /// Returns the transaction found if any
        pub fn tx_found(self) -> Option<groestlcoin::Transaction> {
            self.tx_found
        }
    }
    impl crate::Visitor for FindTransaction {
        fn visit_transaction(&mut self, tx: &crate::bsl::Transaction) -> ControlFlow<()> {
            let current = groestlcoin::Txid::from_slice(tx.txid_sha2().as_slice()).expect("32");
            if self.to_find == current {
                let tx_found = groestlcoin::Transaction::consensus_decode(&mut tx.as_ref())
                    .expect("slice validated");
                self.tx_found = Some(tx_found);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        bsl::{Block, BlockHeader},
        test_common::GENESIS_BLOCK,
        Parse,
    };
    use hex_lit::hex;

    #[test]
    fn parse_block() {
        let block_header = BlockHeader::parse(&GENESIS_BLOCK).unwrap();
        let block = Block::parse(&GENESIS_BLOCK).unwrap();

        assert_eq!(block.remaining(), &[][..]);
        assert_eq!(
            block.parsed(),
            &Block {
                slice: &GENESIS_BLOCK,
                header: block_header.parsed_owned(),
                total_txs: 1
            }
        );
        assert_eq!(block.consumed(), 266);

        // let mut iter = block.parsed.transactions();
        // let genesis_tx = iter.next().unwrap();
        // assert_eq!(genesis_tx.as_ref(), GENESIS_TX);
        // assert!(iter.next().is_none())
    }

    #[cfg(all(feature = "groestlcoin", feature = "sha2"))]
    pub const MAINNET_702861: &[u8] = &hex!("00000020e670e44ffefc209213e8e4be50d96a4deae38b126ef1725c6f120000000000009859ba9b4c5cfa36590f47afdcf15c8a119ab7f62402b87b5229e26a7722a86ed31dce651863161a3952394c04010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff1b036acb4b04d31dce65087cf40181fe48140008754d736457524f62000000000287b4cd1d0000000017a914875ff5ac568b44a58b7f71df71e6d8288725a9a7870000000000000000266a24aa21a9ed48c70464562193b3ff046e75dada4749ba1078c60cfd5929620b6c9000b109f701200000000000000000000000000000000000000000000000000000000000000000000000000200000000010102966eff15d11d2f399ecf47ddce17cf6aa36bca645a20fabc22a1828b02d1760100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff02ee600204000000001600144cfbf0533fd4e69a546b6bdeadb1e6ea4d3a3bb478f2ca19000000001600143025d6826352d12d448be7b6eec94dced19ba6020247304402206c4eca5d53f4f81a79af560fe023a4397f2c14dbe5362fecffdd1e700daf527302206668f0019ca0676f0cef0c0d31f49054153eab711d8f960cebf4a5da39856bdd01210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc53ccb4b0002000000000101cf3edd066bc0396904c911d199ea6719e0fd9f16c0a170cd7a43322303c709ae0000000000fdffffff02ec8f561500000000160014d7f268b46761d83a48e3d51034e2dd86cffd994a73a00b0800000000160014ee37da9991b9dda7abbcca7dd0f05fff374dc78a024730440220658e405c0c014498ceaae873630aa3915d56bfbad8da471a382da684facb542202207f29b302bde452669b8dcb914c69dbbb54fea04dbe6d8b95110106e1d676b2d70121020bd2df55d87b1dfbd6056d903588aab6eb456b93bc4103abc1de34dca661a0ad69cb4b000200000000010466d60031b0f952c31c0aadae41145f1f1149af0e1b2f18944da8b2001353cd640100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff14ef10f598d0026978a3939f600bf48c6cf1ad91fce0048bfe50abc184ad02750100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff580e251d0aa46a5ec3e12a89b658ce623be9ce6d826088147bb7b24c526543730100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff06eaebb3fc394901bb26afb965461c526f25b6af8b09e60c76e33e04021798ad0100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff02f56f690c00000000160014b50e4f02605b7294ae6bc04ccaea0ef5d8e92c0340f5cb6a00000000160014572e7e78b59aa3f5ad90eba0c49d3072e4f6883e024730440220080177e6b1ddc27548eab77ea02efb2e7bdbaa5a7bc75491659e566425022f8e022019de156b11e2f6a842e75abdb4f8b922ddd396945fcb0db8e3420693ed15c54101210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc50247304402206df498a34bdf6fa176515d72b537e70600dc1b965b3cc1f658a26767f32b5ca402202fd99d732d96819368dcc6094be0f0cc9e83616f84de00425ea25f0d8c61ff3401210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc50247304402202d3466f86747d56162f35cbffb0ab992b51e0ca7d164da4da7ad34aea129fa0e02205920a0397e75a669f9c28bcd27e90cb69167f3ece91b9deaca31d5bb9635261701210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc502473044022019a29cbfa3029ad3df6691caa585aa1523b792488f65d290b3e014474eb45e5602205bb244bfeccb8c1657d8e8b428646c720a08eeee74f183a8a6a006cc22c224f801210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc569cb4b00");

    #[cfg(all(feature = "groestlcoin", feature = "sha2"))]
    #[test]
    fn find_tx() {
        use crate::Visit;
        //use bitcoin_test_data::blocks::mainnet_702861;
        use core::str::FromStr;

        //let mainnet_702861 = hex!("00000020e670e44ffefc209213e8e4be50d96a4deae38b126ef1725c6f120000000000009859ba9b4c5cfa36590f47afdcf15c8a119ab7f62402b87b5229e26a7722a86ed31dce651863161a3952394c04010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff1b036acb4b04d31dce65087cf40181fe48140008754d736457524f62000000000287b4cd1d0000000017a914875ff5ac568b44a58b7f71df71e6d8288725a9a7870000000000000000266a24aa21a9ed48c70464562193b3ff046e75dada4749ba1078c60cfd5929620b6c9000b109f701200000000000000000000000000000000000000000000000000000000000000000000000000200000000010102966eff15d11d2f399ecf47ddce17cf6aa36bca645a20fabc22a1828b02d1760100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff02ee600204000000001600144cfbf0533fd4e69a546b6bdeadb1e6ea4d3a3bb478f2ca19000000001600143025d6826352d12d448be7b6eec94dced19ba6020247304402206c4eca5d53f4f81a79af560fe023a4397f2c14dbe5362fecffdd1e700daf527302206668f0019ca0676f0cef0c0d31f49054153eab711d8f960cebf4a5da39856bdd01210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc53ccb4b0002000000000101cf3edd066bc0396904c911d199ea6719e0fd9f16c0a170cd7a43322303c709ae0000000000fdffffff02ec8f561500000000160014d7f268b46761d83a48e3d51034e2dd86cffd994a73a00b0800000000160014ee37da9991b9dda7abbcca7dd0f05fff374dc78a024730440220658e405c0c014498ceaae873630aa3915d56bfbad8da471a382da684facb542202207f29b302bde452669b8dcb914c69dbbb54fea04dbe6d8b95110106e1d676b2d70121020bd2df55d87b1dfbd6056d903588aab6eb456b93bc4103abc1de34dca661a0ad69cb4b000200000000010466d60031b0f952c31c0aadae41145f1f1149af0e1b2f18944da8b2001353cd640100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff14ef10f598d0026978a3939f600bf48c6cf1ad91fce0048bfe50abc184ad02750100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff580e251d0aa46a5ec3e12a89b658ce623be9ce6d826088147bb7b24c526543730100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff06eaebb3fc394901bb26afb965461c526f25b6af8b09e60c76e33e04021798ad0100000017160014187af46a71950196b4665b766f4523f169e6fd4bfdffffff02f56f690c00000000160014b50e4f02605b7294ae6bc04ccaea0ef5d8e92c0340f5cb6a00000000160014572e7e78b59aa3f5ad90eba0c49d3072e4f6883e024730440220080177e6b1ddc27548eab77ea02efb2e7bdbaa5a7bc75491659e566425022f8e022019de156b11e2f6a842e75abdb4f8b922ddd396945fcb0db8e3420693ed15c54101210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc50247304402206df498a34bdf6fa176515d72b537e70600dc1b965b3cc1f658a26767f32b5ca402202fd99d732d96819368dcc6094be0f0cc9e83616f84de00425ea25f0d8c61ff3401210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc50247304402202d3466f86747d56162f35cbffb0ab992b51e0ca7d164da4da7ad34aea129fa0e02205920a0397e75a669f9c28bcd27e90cb69167f3ece91b9deaca31d5bb9635261701210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc502473044022019a29cbfa3029ad3df6691caa585aa1523b792488f65d290b3e014474eb45e5602205bb244bfeccb8c1657d8e8b428646c720a08eeee74f183a8a6a006cc22c224f801210251ffb811aaf0ddfb5c19ca56db4d04be3e71a7f3565178420b9c051f59355fc569cb4b00");

        let txid = groestlcoin::Txid::from_str(
            "facd422e988eae111fae960ea490c3a4599ecbbb7b3adbf876c580f00c44b872",
        )
        .unwrap();
        let mut visitor = crate::bsl::FindTransaction::new(txid.clone());
        let _ = Block::visit(MAINNET_702861, &mut visitor);
        let tx = visitor.tx_found().unwrap();
        assert_eq!(tx.txid(), txid);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn size_of() {
        use core::ops::ControlFlow;

        assert_eq!(std::mem::size_of::<Block>(), 56);

        assert_eq!(std::mem::size_of::<ControlFlow<()>>(), 1);
    }
}

#[cfg(bench)]
mod bench {
    use core::ops::ControlFlow;

    use crate::bsl::{Block, TxOut};
    use crate::{Parse, Visit, Visitor};
    use bitcoin_test_data::blocks::mainnet_702861;
    use groestlcoin::consensus::deserialize;
    use test::{black_box, Bencher};
    use crate::bsl::block::test::MAINNET_702861;

    #[bench]
    pub fn block_deserialize(bh: &mut Bencher) {
        bh.iter(|| {
            let block = Block::parse(mainnet_702861()).unwrap();
            black_box(&block);
        });
        bh.bytes = mainnet_702861().len() as u64;
    }

    #[bench]
    pub fn block_deserialize_bitcoin(bh: &mut Bencher) {
        bh.iter(|| {
            let block: groestlcoin::Block = deserialize(mainnet_702861()).unwrap();
            black_box(&block);
        });
        bh.bytes = mainnet_702861().len() as u64;
    }

    #[bench]
    pub fn block_sum_outputs(bh: &mut Bencher) {
        bh.iter(|| {
            struct Sum(u64);
            impl Visitor for Sum {
                fn visit_tx_out(&mut self, _vout: usize, tx_out: &TxOut) -> ControlFlow<()> {
                    self.0 += tx_out.value();
                    ControlFlow::Continue(())
                }
            }
            let mut sum = Sum(0);
            let block = Block::visit(mainnet_702861(), &mut sum).unwrap();
            assert_eq!(sum.0, 2883682728990);
            black_box(&block);
        });
    }

    #[bench]
    pub fn block_sum_outputs_bitcoin(bh: &mut Bencher) {
        bh.iter(|| {
            let block: groestlcoin::Block = deserialize(mainnet_702861()).unwrap();
            let sum: u64 = block
                .txdata
                .iter()
                .flat_map(|t| t.output.iter())
                .fold(0, |acc, e| acc + e.value.to_sat());
            assert_eq!(sum, 2883682728990);

            black_box(&block);
        });
    }

    #[cfg(feature = "groestlcoin_hashes")]
    #[bench]
    pub fn hash_block_txs(bh: &mut Bencher) {
        use core::ops::ControlFlow;

        use groestlcoin::hashes::sha256;

        bh.iter(|| {
            struct VisitTx(Vec<sha256::Hash>);
            let mut v = VisitTx(vec![]);
            impl crate::Visitor for VisitTx {
                fn visit_block_begin(&mut self, total_transactions: usize) {
                    self.0.reserve(total_transactions);
                }
                fn visit_transaction(&mut self, tx: &crate::bsl::Transaction) -> ControlFlow<()> {
                    self.0.push(tx.txid());
                    ControlFlow::Continue(())
                }
            }

            let block = Block::visit(mainnet_702861(), &mut v).unwrap();

            assert_eq!(v.0.len(), 2500);

            black_box((&block, v));
        });
    }

    #[cfg(feature = "sha2")]
    #[bench]
    pub fn hash_block_txs_sha2(bh: &mut Bencher) {
        use core::ops::ControlFlow;

        bh.iter(|| {
            struct VisitTx(
                Vec<
                    crate::sha2::digest::generic_array::GenericArray<
                        u8,
                        crate::sha2::digest::typenum::U32,
                    >,
                >,
            );
            let mut v = VisitTx(vec![]);
            impl crate::Visitor for VisitTx {
                fn visit_block_begin(&mut self, total_transactions: usize) {
                    self.0.reserve(total_transactions);
                }
                fn visit_transaction(&mut self, tx: &crate::bsl::Transaction) -> ControlFlow<()> {
                    self.0.push(tx.txid_sha2());
                    ControlFlow::Continue(())
                }
            }

            let block = Block::visit(mainnet_702861(), &mut v).unwrap();

            assert_eq!(v.0.len(), 2500);

            black_box((&block, v));
        });
    }

    #[bench]
    pub fn hash_block_txs_bitcoin(bh: &mut Bencher) {
        bh.iter(|| {
            let block: groestlcoin::Block = deserialize(mainnet_702861()).unwrap();
            let mut tx_hashes = Vec::with_capacity(block.txdata.len());

            for tx in block.txdata.iter() {
                tx_hashes.push(tx.txid())
            }
            assert_eq!(tx_hashes.len(), 2500);
            black_box((&block, tx_hashes));
        });
    }

    #[cfg(all(feature = "groestlcoin", feature = "sha2"))]
    #[bench]
    pub fn find_tx(bh: &mut Bencher) {
        use std::str::FromStr;
        let txid = groestlcoin::Txid::from_str(
            "facd422e988eae111fae960ea490c3a4599ecbbb7b3adbf876c580f00c44b872",
        )
        .unwrap();

        bh.iter(|| {
            let mut visitor = crate::bsl::FindTransaction::new(txid.clone());
            let _ = Block::visit(MAINNET_702861, &mut visitor);
            let tx = visitor.tx_found().unwrap();
            assert_eq!(tx.txid(), txid);
            core::hint::black_box(tx);
        });
    }

    #[cfg(feature = "groestlcoin")]
    #[bench]
    pub fn find_tx_bitcoin(bh: &mut Bencher) {
        use std::str::FromStr;
        let txid = groestlcoin::Txid::from_str(
            "facd422e988eae111fae960ea490c3a4599ecbbb7b3adbf876c580f00c44b872",
        )
        .unwrap();
        bh.iter(|| {
            let block: groestlcoin::Block = deserialize(MAINNET_702861).unwrap();
            let mut tx = None;
            for current in block.txdata {
                if current.txid() == txid {
                    tx = Some(current);
                    break;
                }
            }
            let tx = tx.unwrap();
            assert_eq!(tx.txid(), txid);
            core::hint::black_box(&tx);
        });
    }
}
