# halo2-TPCH instruction:
To generate the proofs for SQL queries Q1, Q3, Q5, Q8, Q9 and Q18, please run the following commands at the root of the project.

cargo test --package halo2-experiments --lib -- sql::q1_final_v4::tests::test_1 --exact --nocapture

cargo test --package halo2-experiments --lib -- sql::q3_final_v7::tests::test_1 --exact --nocapture

cargo test --package halo2-experiments --lib -- sql::q5_final_v4::tests::test_1 --exact --nocapture

cargo test --package halo2-experiments --lib -- sql::q8_final_v3::tests::test_1 --exact --nocapture

cargo test --package halo2-experiments --lib -- sql::q9_final_v2::tests::test_1 --exact --nocapture

cargo test --package halo2-experiments --lib -- sql::q18_final_v2::tests::test_1 --exact --nocapture



# Notes:
Please enable sufficient RUST_MIN_STACK by running, e.g., "export RUST_MIN_STACK=33554432"

For different datasets, please choose the correct public parameters. For 60k, 120k, 240k Rows, k = 16, 17, 18 respectively for Q1, Q5, Q8, Q9, Q18. For 60k, 120k, 240k Rows, k = 15, 16, 17 respectively for Q3.


## Citation

If you find our work helpful, please consider citing the following:

@article{gu2025poneglyphdb,
  title={PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification},
  author={Gu, Binbin and Fang, Juncheng and Nawab, Faisal},
  journal={Proceedings of the ACM on Management of Data},
  volume={3},
  number={1},
  pages={1--27},
  year={2025},
  publisher={ACM New York, NY, USA}
}
