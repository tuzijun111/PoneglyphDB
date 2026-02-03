# PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification

## Authors

**Binbin Gu**, **Juncheng Fang**, **Faisal Nawab**
{binbing, junchf1, nawabf}@uci.edu

**PoneglyphDB** provides efficient non-interactive zero-knowledge proofs (NIZKs) for verifying arbitrary SQL queries. This repository includes Halo2 circuits for TPC-H workloads and end-to-end proof generation.

Halo2 circuits for TPC-H workloads and end-to-end proof generation.

---

## 🚀 Halo2-TPCH Instructions

To generate proofs for SQL queries **Q1, Q3, Q5, Q8, Q9, and Q18**, run the following commands from the project root:

```bash
# Query 1
cargo test --package halo2-experiments --lib -- sql::q1_final_v4::tests::test_1 --exact --nocapture

# Query 3
cargo test --package halo2-experiments --lib -- sql::q3_final_v7::tests::test_1 --exact --nocapture

# Query 5
cargo test --package halo2-experiments --lib -- sql::q5_final_v4::tests::test_1 --exact --nocapture

# Query 8
cargo test --package halo2-experiments --lib -- sql::q8_final_v3::tests::test_1 --exact --nocapture

# Query 9
cargo test --package halo2-experiments --lib -- sql::q9_final_v2::tests::test_1 --exact --nocapture

# Query 18
cargo test --package halo2-experiments --lib -- sql::q18_final_v2::tests::test_1 --exact --nocapture
```

---

## 📝 Notes

### **Prerequisite: Stack Size**

Halo2 circuits require a sufficiently large stack size. Set `RUST_MIN_STACK` before generating proofs:

```bash
export RUST_MIN_STACK=33554432
```

---

### **Public Parameter Selection (`k`)**

Select appropriate Halo2 public parameters depending on dataset size:

| Dataset Size | Queries (Q1, Q5, Q8, Q9, Q18) | Query Q3 |
| ------------ | ----------------------------- | -------- |
| 60k Rows     | k = 16                        | k = 15   |
| 120k Rows    | k = 17                        | k = 16   |
| 240k Rows    | k = 18                        | k = 17   |

Note: The necessary parameters are already persisted as param15 through param18. Please be aware that manually configuring the degree ($k$) within the source code is only supported when using the MockProver.
---

## 📚 Citation

If you find our work useful, please consider citing:

```bibtex
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
```
